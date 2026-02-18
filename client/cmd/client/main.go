package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/albahrani/mailx/client/internal/crypto"
	pb "github.com/albahrani/mailx/client/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var debugLogging = os.Getenv("MAILX_CLIENT_DEBUG") != ""

func dbg(format string, args ...any) {
	if !debugLogging {
		return
	}
	log.Printf("DEBUG "+format, args...)
}

// ClientConfig holds client configuration
type ClientConfig struct {
	Username    string `json:"username"`
	Domain      string `json:"domain"`
	ServerAddr  string `json:"serverAddr"`
	PublicKey   string `json:"publicKey"`
	PrivateKey  string `json:"privateKey"`
	AccessToken string `json:"accessToken"`
	TokenExpiry int64  `json:"tokenExpiry"`
}

// Client represents the MailX client
type Client struct {
	config  *ClientConfig
	conn    *grpc.ClientConn
	client  pb.ClientServiceClient
	keyPair *crypto.KeyPair

	signKeyMu    sync.RWMutex
	signKeyCache map[string][]byte // domain -> ed25519 public key
}

type wellKnownResponse struct {
	Version   string `json:"version"`
	Domain    string `json:"domain"`
	PublicKey string `json:"publicKey"`
	SignKey   string `json:"signKey"`
}

func parseAddress(address string) (username, domain string, err error) {
	parts := strings.Split(address, "@")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", fmt.Errorf("invalid address format: %q", address)
	}
	return parts[0], parts[1], nil
}

func keyAttestationPayload(address string, publicKey []byte, createdAtUnix int64) []byte {
	b64 := base64.StdEncoding.EncodeToString(publicKey)
	created := strconv.FormatInt(createdAtUnix, 10)
	return []byte("mailx-key-attestation-v1\n" + address + "\n" + b64 + "\n" + created)
}

func (c *Client) httpClient() *http.Client {
	// Demo behavior: if MAILX_CLIENT_TLS is set, allow HTTPS fetch of well-known even
	// with self-signed certs.
	tr := &http.Transport{}
	if os.Getenv("MAILX_CLIENT_TLS") != "" {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: tr}
}

func (c *Client) fetchSigningKey(ctx context.Context, domain string) ([]byte, error) {
	if strings.TrimSpace(domain) == "" {
		return nil, fmt.Errorf("empty domain")
	}

	c.signKeyMu.RLock()
	if c.signKeyCache != nil {
		if k, ok := c.signKeyCache[domain]; ok {
			c.signKeyMu.RUnlock()
			return k, nil
		}
	}
	c.signKeyMu.RUnlock()

	urls := []string{
		fmt.Sprintf("https://%s/.well-known/mailx-server", domain),
		fmt.Sprintf("http://%s/.well-known/mailx-server", domain),
		fmt.Sprintf("http://%s:8080/.well-known/mailx-server", domain),
	}

	hc := c.httpClient()
	var lastErr error
	for _, url := range urls {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			lastErr = err
			continue
		}

		resp, err := hc.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		func() {
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				lastErr = fmt.Errorf("well-known returned status %d", resp.StatusCode)
				return
			}
			var wk wellKnownResponse
			if err := json.NewDecoder(resp.Body).Decode(&wk); err != nil {
				lastErr = err
				return
			}

			keyStr := wk.SignKey
			if keyStr == "" {
				lastErr = fmt.Errorf("well-known missing signKey")
				return
			}
			k, err := base64.StdEncoding.DecodeString(keyStr)
			if err != nil {
				lastErr = err
				return
			}
			if len(k) != crypto.SigningPublicKeySize {
				lastErr = fmt.Errorf("invalid signing public key size: got %d want %d", len(k), crypto.SigningPublicKeySize)
				return
			}

			c.signKeyMu.Lock()
			if c.signKeyCache == nil {
				c.signKeyCache = make(map[string][]byte)
			}
			c.signKeyCache[domain] = k
			c.signKeyMu.Unlock()

			lastErr = nil
		}()

		if lastErr == nil {
			break
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("failed to fetch signing key for %s: %w", domain, lastErr)
	}

	c.signKeyMu.RLock()
	k := c.signKeyCache[domain]
	c.signKeyMu.RUnlock()
	return k, nil
}

// NewClient creates a new client
func NewClient(configFile string) (*Client, error) {
	var config ClientConfig

	// Try to load existing config
	dbg("loading config file %q", configFile)
	data, err := os.ReadFile(configFile)
	if err == nil {
		if err := json.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("failed to parse config: %w", err)
		}
	} else {
		dbg("config file not loaded (%v); continuing with defaults", err)
	}

	// Load key pair if exists
	var keyPair *crypto.KeyPair
	if config.PrivateKey != "" {
		privKey, err := base64.StdEncoding.DecodeString(config.PrivateKey)
		if err == nil {
			pubKey, err := base64.StdEncoding.DecodeString(config.PublicKey)
			if err == nil {
				keyPair = &crypto.KeyPair{
					PublicKey:  pubKey,
					PrivateKey: privKey,
				}
			} else {
				dbg("failed decoding publicKey: %v", err)
			}
		} else {
			dbg("failed decoding privateKey: %v", err)
		}
	}

	// Connect to server (if configured)
	if strings.TrimSpace(config.ServerAddr) == "" {
		dbg("no serverAddr configured; skipping server connection")
		return &Client{
			config:       &config,
			keyPair:      keyPair,
			signKeyCache: make(map[string][]byte),
		}, nil
	}

	dbg("connecting to server %q", config.ServerAddr)
	creds := insecure.NewCredentials()
	if os.Getenv("MAILX_CLIENT_TLS") != "" {
		creds = credentials.NewTLS(&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
		dbg("TLS enabled for client connection (MAILX_CLIENT_TLS set)")
	}
	conn, err := grpc.NewClient(config.ServerAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	client := pb.NewClientServiceClient(conn)

	return &Client{
		config:       &config,
		conn:         conn,
		client:       client,
		keyPair:      keyPair,
		signKeyCache: make(map[string][]byte),
	}, nil
}

// Close closes the client connection
func (c *Client) Close() {
	if c.conn != nil {
		dbg("closing grpc connection")
		c.conn.Close()
	}
}

// saveConfig saves the client configuration
func (c *Client) saveConfig(configFile string) error {
	data, err := json.MarshalIndent(c.config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configFile, data, 0600)
}

// Register registers a new account
func (c *Client) Register(username, domain, password, serverAddr string) error {
	dbg("register username=%q domain=%q server=%q", username, domain, serverAddr)
	c.config.Username = username
	c.config.Domain = domain
	c.config.ServerAddr = serverAddr

	// Generate key pair
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}
	c.keyPair = keyPair

	// Save keys to config
	c.config.PublicKey = base64.StdEncoding.EncodeToString(keyPair.PublicKey)
	c.config.PrivateKey = base64.StdEncoding.EncodeToString(keyPair.PrivateKey)

	// Reconnect to server
	c.Close()
	dbg("reconnecting to server %q", serverAddr)
	creds := insecure.NewCredentials()
	if os.Getenv("MAILX_CLIENT_TLS") != "" {
		creds = credentials.NewTLS(&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
		dbg("TLS enabled for client connection (MAILX_CLIENT_TLS set)")
	}
	conn, err := grpc.NewClient(serverAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	c.conn = conn
	c.client = pb.NewClientServiceClient(conn)

	// Register with server
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.client.Register(ctx, &pb.RegisterRequest{
		Username:  username,
		Password:  password,
		PublicKey: keyPair.PublicKey,
	})
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	fmt.Printf("Registration successful!\n")
	fmt.Printf("User ID: %s\n", resp.UserId)
	fmt.Printf("Address: %s@%s\n", username, domain)

	return nil
}

// Login logs in to the account
func (c *Client) Login(password string) error {
	dbg("login username=%q", c.config.Username)
	if c.client == nil {
		return fmt.Errorf("not connected to a server (configure serverAddr via config or register)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.client.Login(ctx, &pb.LoginRequest{
		Username: c.config.Username,
		Password: password,
	})
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	c.config.AccessToken = resp.AccessToken
	c.config.TokenExpiry = resp.ExpiresAt

	fmt.Printf("Login successful!\n")
	return nil
}

// SendMessage sends a message
func (c *Client) SendMessage(recipient, subject, body string) error {
	dbg("send to=%q subject_len=%d body_len=%d", recipient, len(subject), len(body))
	if c.client == nil {
		return fmt.Errorf("not connected to a server (configure serverAddr via config or register)")
	}
	if c.config.AccessToken == "" {
		return fmt.Errorf("not logged in")
	}

	// Get recipient's public key
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	keyResp, err := c.client.GetContactKey(ctx, &pb.GetContactKeyRequest{
		AccessToken: c.config.AccessToken,
		Address:     recipient,
	})
	if err != nil {
		return fmt.Errorf("failed to get recipient key: %w", err)
	}

	// Verify server signature over the recipient key (server-authenticated key directory).
	{
		_, keyDomain, err := parseAddress(keyResp.Address)
		if err != nil {
			return err
		}
		signKey, err := c.fetchSigningKey(ctx, keyDomain)
		if err != nil {
			return err
		}
		payload := keyAttestationPayload(keyResp.Address, keyResp.PublicKey, keyResp.CreatedAt)
		if !crypto.VerifySignature(signKey, payload, keyResp.ServerSignature) {
			return fmt.Errorf("recipient key attestation verification failed")
		}
	}

	// Create message payload
	payload := map[string]interface{}{
		"subject":   subject,
		"body":      body,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Encrypt message
	encrypted, nonce, err := crypto.EncryptMessage(payloadJSON, keyResp.PublicKey, c.keyPair.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt message: %w", err)
	}

	// Create encrypted message blob (simplified format)
	messageBlob := map[string]interface{}{
		"nonce":      base64.StdEncoding.EncodeToString(nonce),
		"ciphertext": base64.StdEncoding.EncodeToString(encrypted),
	}
	messageBlobJSON, _ := json.Marshal(messageBlob)

	// Send message
	sendResp, err := c.client.SendMessage(ctx, &pb.SendMessageRequest{
		AccessToken:      c.config.AccessToken,
		Recipients:       []string{recipient},
		EncryptedMessage: messageBlobJSON,
		Metadata: &pb.MessageMetadata{
			Timestamp: time.Now().Unix(),
			Size:      int32(len(messageBlobJSON)),
			Subject:   subject,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	fmt.Printf("Message sent!\n")
	fmt.Printf("Message ID: %s\n", sendResp.MessageId)
	for _, status := range sendResp.DeliveryStatuses {
		fmt.Printf("  %s: %s\n", status.Recipient, status.Status)
		if status.ErrorMessage != "" {
			fmt.Printf("    Error: %s\n", status.ErrorMessage)
		}
	}

	return nil
}

// ListMessages lists messages in a folder
func (c *Client) ListMessages(folder string, limit int) error {
	dbg("list folder=%q limit=%d", folder, limit)
	if c.client == nil {
		return fmt.Errorf("not connected to a server (configure serverAddr via config or register)")
	}
	if c.config.AccessToken == "" {
		return fmt.Errorf("not logged in")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.client.ListMessages(ctx, &pb.ListMessagesRequest{
		AccessToken: c.config.AccessToken,
		Folder:      folder,
		Limit:       int32(limit),
		Offset:      0,
	})
	if err != nil {
		return fmt.Errorf("failed to list messages: %w", err)
	}

	fmt.Printf("\n=== %s (%d messages) ===\n\n", folder, resp.TotalCount)
	for i, msg := range resp.Messages {
		readStatus := " "
		if !msg.Read {
			readStatus = "*"
		}
		timestamp := time.Unix(msg.Timestamp, 0).Format("2006-01-02 15:04")
		fmt.Printf("%s [%d] %s - %s\n", readStatus, i+1, timestamp, msg.Sender)
		fmt.Printf("     Subject: %s\n", msg.Subject)
		fmt.Printf("     ID: %s\n\n", msg.MessageId)
	}

	return nil
}

// ReadMessage reads and decrypts a message
func (c *Client) ReadMessage(messageID string) error {
	dbg("read message_id=%q", messageID)
	if c.client == nil {
		return fmt.Errorf("not connected to a server (configure serverAddr via config or register)")
	}
	if c.config.AccessToken == "" {
		return fmt.Errorf("not logged in")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.client.GetMessage(ctx, &pb.GetMessageRequest{
		AccessToken: c.config.AccessToken,
		MessageId:   messageID,
	})
	if err != nil {
		return fmt.Errorf("failed to get message: %w", err)
	}

	// Parse encrypted blob
	var messageBlob map[string]interface{}
	if err := json.Unmarshal(resp.EncryptedMessage, &messageBlob); err != nil {
		return fmt.Errorf("failed to parse message blob: %w", err)
	}

	nonceStr, _ := messageBlob["nonce"].(string)
	ciphertextStr, _ := messageBlob["ciphertext"].(string)

	nonce, _ := base64.StdEncoding.DecodeString(nonceStr)
	ciphertext, _ := base64.StdEncoding.DecodeString(ciphertextStr)

	// Get sender's public key
	keyResp, err := c.client.GetContactKey(ctx, &pb.GetContactKeyRequest{
		AccessToken: c.config.AccessToken,
		Address:     resp.Sender,
	})
	if err != nil {
		return fmt.Errorf("failed to get sender key: %w", err)
	}

	// Verify server signature over the sender key.
	{
		_, keyDomain, err := parseAddress(keyResp.Address)
		if err != nil {
			return err
		}
		signKey, err := c.fetchSigningKey(ctx, keyDomain)
		if err != nil {
			return err
		}
		payload := keyAttestationPayload(keyResp.Address, keyResp.PublicKey, keyResp.CreatedAt)
		if !crypto.VerifySignature(signKey, payload, keyResp.ServerSignature) {
			return fmt.Errorf("sender key attestation verification failed")
		}
	}

	// Decrypt message
	decrypted, err := crypto.DecryptMessage(ciphertext, nonce, keyResp.PublicKey, c.keyPair.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt message: %w", err)
	}

	// Parse payload
	var payload map[string]interface{}
	if err := json.Unmarshal(decrypted, &payload); err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	// Display message
	fmt.Printf("\n=== Message ===\n")
	fmt.Printf("From: %s\n", resp.Sender)
	fmt.Printf("Subject: %s\n", payload["subject"])
	fmt.Printf("Timestamp: %s\n", payload["timestamp"])
	fmt.Printf("\n%s\n", payload["body"])

	return nil
}

// Interactive runs the interactive CLI
func (c *Client) Interactive(configFile string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("\n=== MailX Client ===")
	fmt.Println("Type 'help' for commands")
	fmt.Println()
	log.Printf("interactive mode started (config=%q debug=%v)", configFile, debugLogging)

	for {
		fmt.Print("> ")
		input, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				log.Printf("stdin closed (EOF); exiting")
				return
			}
			log.Printf("failed reading stdin: %v", err)
			time.Sleep(200 * time.Millisecond)
			continue
		}
		input = strings.TrimSpace(input)

		if input == "" {
			continue
		}

		parts := strings.Fields(input)
		command := parts[0]

		switch command {
		case "help":
			fmt.Println("Commands:")
			fmt.Println("  register <username> <domain> <password> <server>")
			fmt.Println("  login <password>")
			fmt.Println("  send <recipient> <subject> <body>")
			fmt.Println("  list [folder] [limit]")
			fmt.Println("  read <message-id>")
			fmt.Println("  exit")

		case "register":
			if len(parts) < 5 {
				fmt.Println("Usage: register <username> <domain> <password> <server>")
				continue
			}
			if err := c.Register(parts[1], parts[2], parts[3], parts[4]); err != nil {
				fmt.Printf("Error: %v\n", err)
			} else {
				c.saveConfig(configFile)
			}

		case "login":
			if len(parts) < 2 {
				fmt.Println("Usage: login <password>")
				continue
			}
			if err := c.Login(parts[1]); err != nil {
				fmt.Printf("Error: %v\n", err)
			} else {
				c.saveConfig(configFile)
			}

		case "send":
			if len(parts) < 4 {
				fmt.Println("Usage: send <recipient> <subject> <body>")
				continue
			}
			recipient := parts[1]
			subject := parts[2]
			body := strings.Join(parts[3:], " ")
			if err := c.SendMessage(recipient, subject, body); err != nil {
				fmt.Printf("Error: %v\n", err)
			}

		case "list":
			folder := "inbox"
			limit := 10
			if len(parts) > 1 {
				folder = parts[1]
			}
			if len(parts) > 2 {
				fmt.Sscanf(parts[2], "%d", &limit)
			}
			if err := c.ListMessages(folder, limit); err != nil {
				fmt.Printf("Error: %v\n", err)
			}

		case "read":
			if len(parts) < 2 {
				fmt.Println("Usage: read <message-id>")
				continue
			}
			if err := c.ReadMessage(parts[1]); err != nil {
				fmt.Printf("Error: %v\n", err)
			}

		case "exit", "quit":
			fmt.Println("Goodbye!")
			return

		default:
			fmt.Println("Unknown command. Type 'help' for commands.")
		}
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetPrefix("mailx-client ")
	log.Printf("starting (debug=%v)", debugLogging)

	configFile := "client_config.json"
	var cmdArgs []string
	if len(os.Args) > 1 {
		arg1 := os.Args[1]
		if strings.HasSuffix(strings.ToLower(arg1), ".json") {
			configFile = arg1
			cmdArgs = os.Args[2:]
		} else if _, err := os.Stat(arg1); err == nil {
			configFile = arg1
			cmdArgs = os.Args[2:]
		} else {
			cmdArgs = os.Args[1:]
		}
	}

	client, err := NewClient(configFile)
	if err != nil {
		log.Printf("Warning: %v\n", err)
		// Continue anyway, user might want to register
		client = &Client{
			config: &ClientConfig{},
		}
	}
	defer client.Close()

	if len(cmdArgs) > 0 {
		// One-shot command mode:
		//   mailx-client [config.json] <command> [args...]
		command := cmdArgs[0]
		parts := cmdArgs
		switch command {
		case "help":
			fmt.Println("Commands:")
			fmt.Println("  register <username> <domain> <password> <server>")
			fmt.Println("  login <password>")
			fmt.Println("  send <recipient> <subject> <body>")
			fmt.Println("  list [folder] [limit]")
			fmt.Println("  read <message-id>")
			fmt.Println("  exit")
			return

		case "register":
			if len(parts) < 5 {
				log.Printf("Usage: register <username> <domain> <password> <server>")
				os.Exit(2)
			}
			if err := client.Register(parts[1], parts[2], parts[3], parts[4]); err != nil {
				log.Printf("Error: %v", err)
				os.Exit(1)
			}
			_ = client.saveConfig(configFile)
			return

		case "login":
			if len(parts) < 2 {
				log.Printf("Usage: login <password>")
				os.Exit(2)
			}
			if err := client.Login(parts[1]); err != nil {
				log.Printf("Error: %v", err)
				os.Exit(1)
			}
			_ = client.saveConfig(configFile)
			return

		case "send":
			if len(parts) < 4 {
				log.Printf("Usage: send <recipient> <subject> <body>")
				os.Exit(2)
			}
			recipient := parts[1]
			subject := parts[2]
			body := strings.Join(parts[3:], " ")
			if err := client.SendMessage(recipient, subject, body); err != nil {
				log.Printf("Error: %v", err)
				os.Exit(1)
			}
			return

		case "list":
			folder := "inbox"
			limit := 10
			if len(parts) > 1 {
				folder = parts[1]
			}
			if len(parts) > 2 {
				fmt.Sscanf(parts[2], "%d", &limit)
			}
			if err := client.ListMessages(folder, limit); err != nil {
				log.Printf("Error: %v", err)
				os.Exit(1)
			}
			return

		case "read":
			if len(parts) < 2 {
				log.Printf("Usage: read <message-id>")
				os.Exit(2)
			}
			if err := client.ReadMessage(parts[1]); err != nil {
				log.Printf("Error: %v", err)
				os.Exit(1)
			}
			return

		case "accept":
			if len(parts) < 2 {
				log.Printf("Usage: accept <address>")
				os.Exit(2)
			}
			if client.client == nil {
				log.Printf("Error: not connected to a server (configure serverAddr via config or register)")
				os.Exit(1)
			}
			if client.config.AccessToken == "" {
				log.Printf("Error: not logged in")
				os.Exit(1)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, err := client.client.AcceptContact(ctx, &pb.AcceptContactRequest{
				AccessToken: client.config.AccessToken,
				Address:     parts[1],
			})
			if err != nil {
				log.Printf("Error: %v", err)
				os.Exit(1)
			}
			log.Printf("Contact accepted: %s", parts[1])
			return
		}

		log.Printf("Unknown command %q (use 'help')", command)
		os.Exit(2)
	}

	// Run interactive mode
	client.Interactive(configFile)
}
