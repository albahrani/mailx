package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/albahrani/mailx/server/internal/crypto"
	"github.com/albahrani/mailx/server/internal/federation"
	"github.com/albahrani/mailx/server/internal/storage"
	pb "github.com/albahrani/mailx/server/proto"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func (s *Server) federationTransportCreds() credentials.TransportCredentials {
	// Demo behavior: if this server is configured with TLS, assume peers are too.
	// We intentionally skip verification for the demo's self-signed cert.
	if s.config.TLSCertFile != "" && s.config.TLSKeyFile != "" {
		return credentials.NewTLS(&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	}
	return insecure.NewCredentials()
}

// Config holds server configuration
type Config struct {
	Domain         string `json:"domain"`
	GRPCPort       string `json:"grpcPort"`
	HTTPPort       string `json:"httpPort"`
	DatabasePath   string `json:"databasePath"`
	TLSCertFile    string `json:"tlsCertFile"`
	TLSKeyFile     string `json:"tlsKeyFile"`
	ServerKeyFile  string `json:"serverKeyFile"`
	MaxMessageSize int32  `json:"maxMessageSize"`
	DefaultQuota   int64  `json:"defaultQuota"`
}

// Server represents the MailX server
type Server struct {
	config    *Config
	storage   *storage.Storage
	serverKey *crypto.KeyPair
	signKey   *crypto.SigningKeyPair
	discovery *federation.Discovery
	pb.UnimplementedClientServiceServer
	pb.UnimplementedFederationServiceServer
}

// NewServer creates a new server instance
func NewServer(config *Config) (*Server, error) {
	// Initialize storage
	store, err := storage.New(config.DatabasePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	// Load or generate server key
	serverKey, err := loadOrGenerateServerKey(config.ServerKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server key: %w", err)
	}

	// Load or generate server signing key
	signKey, err := loadOrGenerateServerSigningKey(config.ServerKeyFile + ".signing.json")
	if err != nil {
		return nil, fmt.Errorf("failed to load server signing key: %w", err)
	}

	return &Server{
		config:    config,
		storage:   store,
		serverKey: serverKey,
		signKey:   signKey,
		discovery: federation.NewDiscovery(),
	}, nil
}

func loadOrGenerateServerSigningKey(keyFile string) (*crypto.SigningKeyPair, error) {
	data, err := os.ReadFile(keyFile)
	if err == nil {
		var keyData struct {
			PublicKey  string `json:"publicKey"`
			PrivateKey string `json:"privateKey"`
		}
		if err := json.Unmarshal(data, &keyData); err == nil {
			privKey, err := base64.StdEncoding.DecodeString(keyData.PrivateKey)
			if err == nil && len(privKey) == crypto.SigningPrivateKeySize {
				pubKey, err := base64.StdEncoding.DecodeString(keyData.PublicKey)
				if err == nil && len(pubKey) == crypto.SigningPublicKeySize {
					return &crypto.SigningKeyPair{PublicKey: pubKey, PrivateKey: privKey}, nil
				}
			}
		}
	}

	log.Println("Generating new server signing key pair...")
	kp, err := crypto.GenerateSigningKeyPair()
	if err != nil {
		return nil, err
	}

	keyData := struct {
		PublicKey  string `json:"publicKey"`
		PrivateKey string `json:"privateKey"`
	}{
		PublicKey:  base64.StdEncoding.EncodeToString(kp.PublicKey),
		PrivateKey: base64.StdEncoding.EncodeToString(kp.PrivateKey),
	}

	data, err = json.MarshalIndent(keyData, "", "  ")
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(keyFile, data, 0600); err != nil {
		return nil, err
	}

	log.Printf("Server signing key saved to %s\n", keyFile)
	return kp, nil
}

// loadOrGenerateServerKey loads the server key from file or generates a new one
func loadOrGenerateServerKey(keyFile string) (*crypto.KeyPair, error) {
	// Try to load existing key
	data, err := os.ReadFile(keyFile)
	if err == nil {
		// Parse the key file (JSON format)
		var keyData struct {
			PublicKey  string `json:"publicKey"`
			PrivateKey string `json:"privateKey"`
		}
		if err := json.Unmarshal(data, &keyData); err == nil {
			privKey, err := base64.StdEncoding.DecodeString(keyData.PrivateKey)
			if err == nil && len(privKey) == crypto.PrivateKeySize {
				pubKey, err := base64.StdEncoding.DecodeString(keyData.PublicKey)
				if err == nil && len(pubKey) == crypto.PublicKeySize {
					return &crypto.KeyPair{
						PublicKey:  pubKey,
						PrivateKey: privKey,
					}, nil
				}
			}
		}
	}

	// Generate new key
	log.Println("Generating new server key pair...")
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	// Save to file
	keyData := struct {
		PublicKey  string `json:"publicKey"`
		PrivateKey string `json:"privateKey"`
	}{
		PublicKey:  base64.StdEncoding.EncodeToString(keyPair.PublicKey),
		PrivateKey: base64.StdEncoding.EncodeToString(keyPair.PrivateKey),
	}

	data, err = json.MarshalIndent(keyData, "", "  ")
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(keyFile, data, 0600); err != nil {
		return nil, err
	}

	log.Printf("Server key saved to %s\n", keyFile)
	log.Printf("Public key: %s\n", keyData.PublicKey)

	return keyPair, nil
}

// Register implements the Register RPC
func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	// Validate input
	if req.Username == "" || req.Password == "" || len(req.PublicKey) != crypto.PublicKeySize {
		return nil, status.Error(codes.InvalidArgument, "invalid registration data")
	}

	// Check if user already exists
	_, err := s.storage.GetUser(req.Username, s.config.Domain)
	if err == nil {
		return nil, status.Error(codes.AlreadyExists, "user already exists")
	}

	// Create user
	userID := uuid.New().String()
	passwordHash := crypto.HashPassword(req.Password)

	// Sign the user's public key (attestation)
	address := federation.FormatAddress(req.Username, s.config.Domain)
	createdAt := time.Now()
	attestationData := federation.KeyAttestationPayload(address, req.PublicKey, createdAt.Unix())
	serverSignature := s.signKey.Sign(attestationData)

	user := &storage.User{
		ID:              userID,
		Username:        req.Username,
		Domain:          s.config.Domain,
		PasswordHash:    passwordHash,
		PublicKey:       req.PublicKey,
		ServerSignature: serverSignature,
		CreatedAt:       createdAt,
		QuotaBytes:      s.config.DefaultQuota,
	}

	if err := s.storage.CreateUser(user); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create user: %v", err)
	}

	return &pb.RegisterResponse{
		UserId:          userID,
		ServerSignature: serverSignature,
		Message:         "Registration successful",
	}, nil
}

// Login implements the Login RPC
func (s *Server) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	user, err := s.storage.GetUser(req.Username, s.config.Domain)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	if !crypto.VerifyPassword(req.Password, user.PasswordHash) {
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	// Generate access token (simplified JWT)
	token := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%d", user.ID, time.Now().Unix())))
	expiresAt := time.Now().Add(1 * time.Hour).Unix()

	return &pb.LoginResponse{
		AccessToken: token,
		ExpiresAt:   expiresAt,
		Message:     "Login successful",
	}, nil
}

// SendMessage implements the SendMessage RPC
func (s *Server) SendMessage(ctx context.Context, req *pb.SendMessageRequest) (*pb.SendMessageResponse, error) {
	// Validate token and get user
	userID, err := s.validateToken(req.AccessToken)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}

	user, err := s.storage.GetUserByID(userID)
	if err != nil {
		return nil, status.Error(codes.Internal, "user not found")
	}

	messageID := uuid.New().String()
	timestamp := time.Now()
	senderAddress := federation.FormatAddress(user.Username, user.Domain)

	var deliveryStatuses []*pb.DeliveryStatus

	for _, recipient := range req.Recipients {
		// Parse recipient address
		recipientUser, recipientDomain, err := federation.ParseAddress(recipient)
		if err != nil {
			deliveryStatuses = append(deliveryStatuses, &pb.DeliveryStatus{
				Recipient:    recipient,
				Status:       pb.DeliveryStatus_FAILED,
				ErrorMessage: "invalid address format",
			})
			continue
		}

		// Check if local or remote delivery
		if recipientDomain == s.config.Domain {
			// Local delivery
			err := s.deliverLocal(recipientUser, senderAddress, req.EncryptedMessage, req.Metadata)
			if err != nil {
				deliveryStatuses = append(deliveryStatuses, &pb.DeliveryStatus{
					Recipient:    recipient,
					Status:       pb.DeliveryStatus_FAILED,
					ErrorMessage: err.Error(),
				})
			} else {
				deliveryStatuses = append(deliveryStatuses, &pb.DeliveryStatus{
					Recipient: recipient,
					Status:    pb.DeliveryStatus_DELIVERED,
				})
			}
		} else {
			// Remote delivery (demo): discover recipient server and forward via federation gRPC.
			ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)

			info, err := s.discovery.DiscoverServer(ctx2, recipientDomain)
			if err != nil {
				cancel()
				deliveryStatuses = append(deliveryStatuses, &pb.DeliveryStatus{
					Recipient:    recipient,
					Status:       pb.DeliveryStatus_FAILED,
					ErrorMessage: fmt.Sprintf("server discovery failed: %v", err),
				})
				continue
			}

			conn, err := grpc.NewClient(info.Endpoint, grpc.WithTransportCredentials(s.federationTransportCreds()))
			if err != nil {
				cancel()
				deliveryStatuses = append(deliveryStatuses, &pb.DeliveryStatus{
					Recipient:    recipient,
					Status:       pb.DeliveryStatus_FAILED,
					ErrorMessage: fmt.Sprintf("failed to connect to remote server: %v", err),
				})
				continue
			}
			fClient := pb.NewFederationServiceClient(conn)
			fResp, err := fClient.DeliverMessage(ctx2, &pb.DeliverMessageRequest{
				Sender:           senderAddress,
				Recipient:        recipient,
				EncryptedMessage: req.EncryptedMessage,
				Metadata: &pb.FederationMessageMetadata{
					Timestamp: req.Metadata.Timestamp,
					Size:      req.Metadata.Size,
					Subject:   req.Metadata.Subject,
				},
				SenderServerSignature: nil,
			})
			conn.Close()
			cancel()

			if err != nil {
				deliveryStatuses = append(deliveryStatuses, &pb.DeliveryStatus{
					Recipient:    recipient,
					Status:       pb.DeliveryStatus_FAILED,
					ErrorMessage: fmt.Sprintf("remote delivery failed: %v", err),
				})
				continue
			}

			switch fResp.Status {
			case pb.DeliverMessageResponse_ACCEPTED:
				deliveryStatuses = append(deliveryStatuses, &pb.DeliveryStatus{
					Recipient: recipient,
					Status:    pb.DeliveryStatus_DELIVERED,
				})
			default:
				deliveryStatuses = append(deliveryStatuses, &pb.DeliveryStatus{
					Recipient:    recipient,
					Status:       pb.DeliveryStatus_FAILED,
					ErrorMessage: fResp.ErrorMessage,
				})
			}
		}
	}

	// Store in sent folder
	sentMsg := &storage.Message{
		ID:              messageID,
		RecipientUserID: userID,
		SenderAddress:   senderAddress,
		EncryptedBlob:   req.EncryptedMessage,
		Subject:         req.Metadata.Subject,
		Timestamp:       timestamp,
		Size:            req.Metadata.Size,
		Read:            true,
		Folder:          "sent",
	}
	s.storage.CreateMessage(sentMsg)

	return &pb.SendMessageResponse{
		MessageId:        messageID,
		Timestamp:        timestamp.Unix(),
		DeliveryStatuses: deliveryStatuses,
	}, nil
}

// deliverLocal delivers a message to a local user
func (s *Server) deliverLocal(username, sender string, encryptedMessage []byte, metadata *pb.MessageMetadata) error {
	recipient, err := s.storage.GetUser(username, s.config.Domain)
	if err != nil {
		return fmt.Errorf("recipient not found")
	}

	// Check contact trust level
	contact, err := s.storage.GetContact(recipient.ID, sender)
	folder := "inbox"
	if contact == nil || contact.TrustLevel == "unknown" {
		folder = "requests"
		// Create contact if doesn't exist
		if contact == nil {
			s.storage.UpsertContact(&storage.Contact{
				UserID:     recipient.ID,
				Address:    sender,
				TrustLevel: "unknown",
				FirstSeen:  time.Now(),
			})
		}
	}

	// Store message
	msg := &storage.Message{
		ID:              uuid.New().String(),
		RecipientUserID: recipient.ID,
		SenderAddress:   sender,
		EncryptedBlob:   encryptedMessage,
		Subject:         metadata.Subject,
		Timestamp:       time.Now(),
		Size:            metadata.Size,
		Read:            false,
		Folder:          folder,
	}

	return s.storage.CreateMessage(msg)
}

// ListMessages implements the ListMessages RPC
func (s *Server) ListMessages(ctx context.Context, req *pb.ListMessagesRequest) (*pb.ListMessagesResponse, error) {
	userID, err := s.validateToken(req.AccessToken)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}

	limit := req.Limit
	if limit <= 0 || limit > 100 {
		limit = 30
	}

	folder := req.Folder
	if folder == "" {
		folder = "inbox"
	}

	messages, total, err := s.storage.ListMessages(userID, folder, int(limit), int(req.Offset))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list messages: %v", err)
	}

	var summaries []*pb.MessageSummary
	for _, msg := range messages {
		summaries = append(summaries, &pb.MessageSummary{
			MessageId: msg.ID,
			Sender:    msg.SenderAddress,
			Subject:   msg.Subject,
			Timestamp: msg.Timestamp.Unix(),
			Size:      msg.Size,
			Read:      msg.Read,
		})
	}

	return &pb.ListMessagesResponse{
		Messages:   summaries,
		TotalCount: int32(total),
	}, nil
}

// GetMessage implements the GetMessage RPC
func (s *Server) GetMessage(ctx context.Context, req *pb.GetMessageRequest) (*pb.GetMessageResponse, error) {
	userID, err := s.validateToken(req.AccessToken)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}

	msg, err := s.storage.GetMessage(req.MessageId, userID)
	if err != nil {
		return nil, status.Error(codes.NotFound, "message not found")
	}

	return &pb.GetMessageResponse{
		MessageId:        msg.ID,
		Sender:           msg.SenderAddress,
		EncryptedMessage: msg.EncryptedBlob,
		Metadata: &pb.MessageMetadata{
			Timestamp: msg.Timestamp.Unix(),
			Size:      msg.Size,
			Subject:   msg.Subject,
		},
	}, nil
}

// GetContactKey implements the GetContactKey RPC
func (s *Server) GetContactKey(ctx context.Context, req *pb.GetContactKeyRequest) (*pb.GetContactKeyResponse, error) {
	username, domain, err := federation.ParseAddress(req.Address)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid address")
	}

	if domain == s.config.Domain {
		user, err := s.storage.GetUser(username, domain)
		if err != nil {
			return nil, status.Error(codes.NotFound, "user not found")
		}

		// Sanity check our own stored signature before returning it.
		payload := federation.KeyAttestationPayload(req.Address, user.PublicKey, user.CreatedAt.Unix())
		if !crypto.VerifySignature(s.signKey.PublicKey, payload, user.ServerSignature) {
			return nil, status.Error(codes.Internal, "invalid server signature for user key")
		}

		return &pb.GetContactKeyResponse{
			Address:         req.Address,
			PublicKey:       user.PublicKey,
			ServerSignature: user.ServerSignature,
			CreatedAt:       user.CreatedAt.Unix(),
		}, nil
	}

	// Remote lookup (demo): discover recipient server and fetch key via federation.
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)

	info, err := s.discovery.DiscoverServer(ctx2, domain)
	if err != nil {
		cancel()
		return nil, status.Errorf(codes.Unavailable, "server discovery failed: %v", err)
	}

	conn, err := grpc.NewClient(info.Endpoint, grpc.WithTransportCredentials(s.federationTransportCreds()))
	if err != nil {
		cancel()
		return nil, status.Errorf(codes.Unavailable, "failed to connect to remote server: %v", err)
	}
	defer conn.Close()

	fClient := pb.NewFederationServiceClient(conn)
	fResp, err := fClient.GetUserKey(ctx2, &pb.GetUserKeyRequest{Address: req.Address})
	cancel()
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "remote key lookup failed: %v", err)
	}

	// Verify remote server's signature over the key it returned.
	payload := federation.KeyAttestationPayload(fResp.Address, fResp.PublicKey, fResp.CreatedAt)
	if info.PublicKey == nil || !crypto.VerifySignature(info.PublicKey, payload, fResp.ServerSignature) {
		return nil, status.Error(codes.Unavailable, "remote key attestation verification failed")
	}

	return &pb.GetContactKeyResponse{
		Address:         fResp.Address,
		PublicKey:       fResp.PublicKey,
		ServerSignature: fResp.ServerSignature,
		CreatedAt:       fResp.CreatedAt,
	}, nil
}

// AcceptContact promotes a contact from "unknown" to "accepted".
func (s *Server) AcceptContact(ctx context.Context, req *pb.AcceptContactRequest) (*pb.AcceptContactResponse, error) {
	userID, err := s.validateToken(req.AccessToken)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}
	if strings.TrimSpace(req.Address) == "" {
		return nil, status.Error(codes.InvalidArgument, "address required")
	}
	if _, _, err := federation.ParseAddress(req.Address); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid address")
	}

	// Upsert contact as accepted.
	if err := s.storage.UpsertContact(&storage.Contact{
		UserID:     userID,
		Address:    req.Address,
		TrustLevel: "accepted",
		FirstSeen:  time.Now(),
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to accept contact: %v", err)
	}

	// Move existing first-contact messages from requests -> inbox.
	if err := s.storage.MoveMessages(userID, req.Address, "requests", "inbox"); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to move messages to inbox: %v", err)
	}

	return &pb.AcceptContactResponse{Message: "contact accepted"}, nil
}

// GetUserKey implements the federation GetUserKey RPC
func (s *Server) GetUserKey(ctx context.Context, req *pb.GetUserKeyRequest) (*pb.GetUserKeyResponse, error) {
	username, domain, err := federation.ParseAddress(req.Address)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid address")
	}

	if domain != s.config.Domain {
		return nil, status.Error(codes.InvalidArgument, "wrong domain")
	}

	user, err := s.storage.GetUser(username, domain)
	if err != nil {
		return nil, status.Error(codes.NotFound, "user not found")
	}

	return &pb.GetUserKeyResponse{
		Address:         req.Address,
		PublicKey:       user.PublicKey,
		ServerSignature: user.ServerSignature,
		CreatedAt:       user.CreatedAt.Unix(),
	}, nil
}

// GetServerInfo implements the GetServerInfo RPC
func (s *Server) GetServerInfo(ctx context.Context, req *pb.ServerInfoRequest) (*pb.ServerInfoResponse, error) {
	return &pb.ServerInfoResponse{
		Domain:    s.config.Domain,
		PublicKey: s.serverKey.PublicKey,
		Version:   "1.0",
		Capabilities: &pb.ServerCapabilities{
			SupportsE2Ee:   true,
			MaxMessageSize: s.config.MaxMessageSize,
		},
	}, nil
}

// DeliverMessage implements the federation DeliverMessage RPC
func (s *Server) DeliverMessage(ctx context.Context, req *pb.DeliverMessageRequest) (*pb.DeliverMessageResponse, error) {
	// Parse recipient
	username, domain, err := federation.ParseAddress(req.Recipient)
	if err != nil {
		return &pb.DeliverMessageResponse{
			Status:       pb.DeliverMessageResponse_REJECTED_NO_SUCH_USER,
			ErrorMessage: "invalid recipient address",
		}, nil
	}

	if domain != s.config.Domain {
		return &pb.DeliverMessageResponse{
			Status:       pb.DeliverMessageResponse_REJECTED_NO_SUCH_USER,
			ErrorMessage: "wrong domain",
		}, nil
	}

	// Deliver to local user
	metadata := &pb.MessageMetadata{
		Timestamp: req.Metadata.Timestamp,
		Size:      req.Metadata.Size,
		Subject:   req.Metadata.Subject,
	}
	err = s.deliverLocal(username, req.Sender, req.EncryptedMessage, metadata)
	if err != nil {
		return &pb.DeliverMessageResponse{
			Status:       pb.DeliverMessageResponse_REJECTED_NO_SUCH_USER,
			ErrorMessage: err.Error(),
		}, nil
	}

	return &pb.DeliverMessageResponse{
		Status:    pb.DeliverMessageResponse_ACCEPTED,
		MessageId: uuid.New().String(),
		Timestamp: time.Now().Unix(),
	}, nil
}

// validateToken validates an access token and returns the user ID
func (s *Server) validateToken(token string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", fmt.Errorf("invalid token")
	}

	// Simple token format: userID:timestamp
	// In production, use proper JWT
	parts := string(decoded)
	sep := strings.LastIndexByte(parts, ':')
	if sep <= 0 || sep >= len(parts)-1 {
		return "", fmt.Errorf("invalid token format")
	}
	userID := parts[:sep]
	var timestamp int64
	if _, err := fmt.Sscanf(parts[sep+1:], "%d", &timestamp); err != nil {
		return "", fmt.Errorf("invalid token format")
	}

	// Check expiration (1 hour)
	if time.Now().Unix()-timestamp > 3600 {
		return "", fmt.Errorf("token expired")
	}

	return userID, nil
}

// serveWellKnown serves the .well-known endpoint
func (s *Server) serveWellKnown(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"version":   "1.0",
		"domain":    s.config.Domain,
		"publicKey": base64.StdEncoding.EncodeToString(s.serverKey.PublicKey),
		"signKey":   base64.StdEncoding.EncodeToString(s.signKey.PublicKey),
		"endpoints": map[string]string{
			"grpc": fmt.Sprintf("%s:%s", s.config.Domain, s.config.GRPCPort),
		},
		"created": time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Run starts the server
func (s *Server) Run() error {
	// Start HTTP server for well-known endpoint
	http.HandleFunc("/.well-known/mailx-server", s.serveWellKnown)
	go func() {
		log.Printf("Starting HTTP server on :%s\n", s.config.HTTPPort)
		if err := http.ListenAndServe(":"+s.config.HTTPPort, nil); err != nil {
			log.Printf("HTTP server error: %v\n", err)
		}
	}()

	// Load TLS credentials
	var opts []grpc.ServerOption
	if s.config.TLSCertFile != "" && s.config.TLSKeyFile != "" {
		creds, err := credentials.NewServerTLSFromFile(s.config.TLSCertFile, s.config.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("failed to load TLS credentials: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
		log.Println("TLS enabled for gRPC server")
	} else {
		log.Println("WARNING: Running gRPC server without TLS (insecure)")
	}

	// Create gRPC server
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterClientServiceServer(grpcServer, s)
	pb.RegisterFederationServiceServer(grpcServer, s)

	// Start listening
	lis, err := net.Listen("tcp", ":"+s.config.GRPCPort)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	log.Printf("Starting gRPC server on :%s\n", s.config.GRPCPort)
	log.Printf("Domain: %s\n", s.config.Domain)
	log.Printf("Server encryption public key: %s\n", base64.StdEncoding.EncodeToString(s.serverKey.PublicKey))
	log.Printf("Server signing public key: %s\n", base64.StdEncoding.EncodeToString(s.signKey.PublicKey))

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down server...")
		grpcServer.GracefulStop()
		s.storage.Close()
	}()

	return grpcServer.Serve(lis)
}

func main() {
	// Load config
	configFile := "config.json"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}

	configData, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}

	var config Config
	if err := json.Unmarshal(configData, &config); err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	// Set defaults
	if config.GRPCPort == "" {
		config.GRPCPort = "8443"
	}
	if config.HTTPPort == "" {
		config.HTTPPort = "8080"
	}
	if config.MaxMessageSize == 0 {
		config.MaxMessageSize = 26214400 // 25 MB
	}
	if config.DefaultQuota == 0 {
		config.DefaultQuota = 10737418240 // 10 GB
	}

	// Create and run server
	server, err := NewServer(&config)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := server.Run(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
