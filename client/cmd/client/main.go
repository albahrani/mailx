package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/albahrani/mailx/client/internal/crypto"
	pb "github.com/albahrani/mailx/client/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// ClientConfig holds client configuration
type ClientConfig struct {
	Username     string `json:"username"`
	Domain       string `json:"domain"`
	ServerAddr   string `json:"serverAddr"`
	PublicKey    string `json:"publicKey"`
	PrivateKey   string `json:"privateKey"`
	AccessToken  string `json:"accessToken"`
	TokenExpiry  int64  `json:"tokenExpiry"`
}

// Client represents the MailX client
type Client struct {
	config *ClientConfig
	conn   *grpc.ClientConn
	client pb.ClientServiceClient
	keyPair *crypto.KeyPair
}

// NewClient creates a new client
func NewClient(configFile string) (*Client, error) {
	var config ClientConfig
	
	// Try to load existing config
	data, err := os.ReadFile(configFile)
	if err == nil {
		if err := json.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("failed to parse config: %w", err)
		}
	}

	// Connect to server
	conn, err := grpc.NewClient(config.ServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	client := pb.NewClientServiceClient(conn)

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
			}
		}
	}

	return &Client{
		config:  &config,
		conn:    conn,
		client:  client,
		keyPair: keyPair,
	}, nil
}

// Close closes the client connection
func (c *Client) Close() {
	if c.conn != nil {
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
	conn, err := grpc.NewClient(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
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

	// Create message payload
	payload := map[string]interface{}{
		"subject": subject,
		"body":    body,
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
		AccessToken: c.config.AccessToken,
		Recipients:  []string{recipient},
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
	fmt.Println("Type 'help' for commands\n")

	for {
		fmt.Print("> ")
		input, _ := reader.ReadString('\n')
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
	configFile := "client_config.json"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
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

	// Run interactive mode
	client.Interactive(configFile)
}
