package app

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
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

// Config holds server configuration.
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

// Server represents the MailX server.
//
// This is the importable core implementation; cmd/server should only do config
// and process wiring (listeners, signal handling, etc.).
type Server struct {
	config    *Config
	storage   *storage.Storage
	serverKey *crypto.KeyPair
	signKey   *crypto.SigningKeyPair
	discovery *federation.Discovery

	// discoveryOverride allows tests to bypass HTTP discovery.
	discoveryOverride map[string]*federation.ServerInfo

	// Federation dialing hook for tests.
	federationDial func(ctx context.Context, endpoint string, creds credentials.TransportCredentials) (*grpc.ClientConn, error)

	pb.UnimplementedClientServiceServer
	pb.UnimplementedFederationServiceServer
}

func (s *Server) discoverServer(ctx context.Context, domain string) (*federation.ServerInfo, error) {
	if s.discoveryOverride != nil {
		if info, ok := s.discoveryOverride[domain]; ok {
			return info, nil
		}
		return nil, fmt.Errorf("server discovery failed: no override for %s", domain)
	}
	return s.discovery.DiscoverServer(ctx, domain)
}

// SigningPublicKey returns the server's Ed25519 signing public key used for
// key attestations.
func (s *Server) SigningPublicKey() []byte {
	if s == nil || s.signKey == nil {
		return nil
	}
	return s.signKey.PublicKey
}

// NewServer creates a new server instance.
func NewServer(config *Config) (*Server, error) {
	store, err := storage.New(config.DatabasePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	serverKey, err := loadOrGenerateServerKey(config.ServerKeyFile)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("failed to load server key: %w", err)
	}

	signKey, err := loadOrGenerateServerSigningKey(config.ServerKeyFile + ".signing.json")
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("failed to load server signing key: %w", err)
	}

	s := &Server{
		config:    config,
		storage:   store,
		serverKey: serverKey,
		signKey:   signKey,
		discovery: federation.NewDiscovery(),
	}
	s.federationDial = func(ctx context.Context, endpoint string, creds credentials.TransportCredentials) (*grpc.ClientConn, error) {
		return grpc.NewClient(endpoint, grpc.WithTransportCredentials(creds))
	}
	return s, nil
}

func (s *Server) Close() error {
	if s.storage == nil {
		return nil
	}
	return s.storage.Close()
}

// RegisterGRPC registers gRPC services on the provided server.
func (s *Server) RegisterGRPC(gs *grpc.Server) {
	pb.RegisterClientServiceServer(gs, s)
	pb.RegisterFederationServiceServer(gs, s)
}

func (s *Server) federationTransportCreds() credentials.TransportCredentials {
	// Demo behavior: if this server is configured with TLS, assume peers are too.
	// We intentionally skip verification for the demo's self-signed cert.
	if s.config.TLSCertFile != "" && s.config.TLSKeyFile != "" {
		return credentials.NewTLS(&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	}
	return insecure.NewCredentials()
}

// WellKnownHandler is a http.HandlerFunc for /.well-known/mailx-server.
func (s *Server) WellKnownHandler(w http.ResponseWriter, _ *http.Request) {
	response := map[string]any{
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
	_ = json.NewEncoder(w).Encode(response)
}

// Register implements the Register RPC.
func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	if req.Username == "" || req.Password == "" || len(req.PublicKey) != crypto.PublicKeySize {
		return nil, status.Error(codes.InvalidArgument, "invalid registration data")
	}

	if _, err := s.storage.GetUser(req.Username, s.config.Domain); err == nil {
		return nil, status.Error(codes.AlreadyExists, "user already exists")
	}

	userID := uuid.New().String()
	passwordHash := crypto.HashPassword(req.Password)

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

	return &pb.RegisterResponse{UserId: userID, ServerSignature: serverSignature, Message: "Registration successful"}, nil
}

// Login implements the Login RPC.
func (s *Server) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	user, err := s.storage.GetUser(req.Username, s.config.Domain)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}
	if !crypto.VerifyPassword(req.Password, user.PasswordHash) {
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	token := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%d", user.ID, time.Now().Unix())))
	expiresAt := time.Now().Add(1 * time.Hour).Unix()

	return &pb.LoginResponse{AccessToken: token, ExpiresAt: expiresAt, Message: "Login successful"}, nil
}

// SendMessage implements the SendMessage RPC.
func (s *Server) SendMessage(ctx context.Context, req *pb.SendMessageRequest) (*pb.SendMessageResponse, error) {
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
		recipientUser, recipientDomain, err := federation.ParseAddress(recipient)
		if err != nil {
			deliveryStatuses = append(deliveryStatuses, &pb.DeliveryStatus{Recipient: recipient, Status: pb.DeliveryStatus_FAILED, ErrorMessage: "invalid address format"})
			continue
		}

		if recipientDomain == s.config.Domain {
			err := s.deliverLocal(recipientUser, senderAddress, req.EncryptedMessage, req.Metadata)
			if err != nil {
				deliveryStatuses = append(deliveryStatuses, &pb.DeliveryStatus{Recipient: recipient, Status: pb.DeliveryStatus_FAILED, ErrorMessage: err.Error()})
			} else {
				deliveryStatuses = append(deliveryStatuses, &pb.DeliveryStatus{Recipient: recipient, Status: pb.DeliveryStatus_DELIVERED})
			}
			continue
		}

		// Remote delivery (demo): discover recipient server and forward via federation gRPC.
		ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
		info, err := s.discoverServer(ctx2, recipientDomain)
		if err != nil {
			cancel()
			deliveryStatuses = append(deliveryStatuses, &pb.DeliveryStatus{Recipient: recipient, Status: pb.DeliveryStatus_FAILED, ErrorMessage: fmt.Sprintf("server discovery failed: %v", err)})
			continue
		}

		conn, err := s.federationDial(ctx2, info.Endpoint, s.federationTransportCreds())
		if err != nil {
			cancel()
			deliveryStatuses = append(deliveryStatuses, &pb.DeliveryStatus{Recipient: recipient, Status: pb.DeliveryStatus_FAILED, ErrorMessage: fmt.Sprintf("failed to connect to remote server: %v", err)})
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
		_ = conn.Close()
		cancel()
		if err != nil {
			deliveryStatuses = append(deliveryStatuses, &pb.DeliveryStatus{Recipient: recipient, Status: pb.DeliveryStatus_FAILED, ErrorMessage: fmt.Sprintf("remote delivery failed: %v", err)})
			continue
		}

		switch fResp.Status {
		case pb.DeliverMessageResponse_ACCEPTED:
			deliveryStatuses = append(deliveryStatuses, &pb.DeliveryStatus{Recipient: recipient, Status: pb.DeliveryStatus_DELIVERED})
		default:
			deliveryStatuses = append(deliveryStatuses, &pb.DeliveryStatus{Recipient: recipient, Status: pb.DeliveryStatus_FAILED, ErrorMessage: fResp.ErrorMessage})
		}
	}

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
	_ = s.storage.CreateMessage(sentMsg)

	return &pb.SendMessageResponse{MessageId: messageID, Timestamp: timestamp.Unix(), DeliveryStatuses: deliveryStatuses}, nil
}

func (s *Server) deliverLocal(username, sender string, encryptedMessage []byte, metadata *pb.MessageMetadata) error {
	recipient, err := s.storage.GetUser(username, s.config.Domain)
	if err != nil {
		return fmt.Errorf("recipient not found")
	}

	contact, err := s.storage.GetContact(recipient.ID, sender)
	folder := "inbox"
	if contact == nil || contact.TrustLevel == "unknown" {
		folder = "requests"
		if contact == nil {
			_ = s.storage.UpsertContact(&storage.Contact{UserID: recipient.ID, Address: sender, TrustLevel: "unknown", FirstSeen: time.Now()})
		}
	}
	_ = err

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

// ListMessages implements the ListMessages RPC.
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

	return &pb.ListMessagesResponse{Messages: summaries, TotalCount: int32(total)}, nil
}

// GetMessage implements the GetMessage RPC.
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
		Metadata:         &pb.MessageMetadata{Timestamp: msg.Timestamp.Unix(), Size: msg.Size, Subject: msg.Subject},
	}, nil
}

// GetContactKey implements the GetContactKey RPC.
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
		payload := federation.KeyAttestationPayload(req.Address, user.PublicKey, user.CreatedAt.Unix())
		if !crypto.VerifySignature(s.signKey.PublicKey, payload, user.ServerSignature) {
			return nil, status.Error(codes.Internal, "invalid server signature for user key")
		}
		return &pb.GetContactKeyResponse{Address: req.Address, PublicKey: user.PublicKey, ServerSignature: user.ServerSignature, CreatedAt: user.CreatedAt.Unix()}, nil
	}

	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	info, err := s.discoverServer(ctx2, domain)
	if err != nil {
		cancel()
		return nil, status.Errorf(codes.Unavailable, "server discovery failed: %v", err)
	}

	conn, err := s.federationDial(ctx2, info.Endpoint, s.federationTransportCreds())
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

	payload := federation.KeyAttestationPayload(fResp.Address, fResp.PublicKey, fResp.CreatedAt)
	if info.PublicKey == nil || !crypto.VerifySignature(info.PublicKey, payload, fResp.ServerSignature) {
		return nil, status.Error(codes.Unavailable, "remote key attestation verification failed")
	}

	return &pb.GetContactKeyResponse{Address: fResp.Address, PublicKey: fResp.PublicKey, ServerSignature: fResp.ServerSignature, CreatedAt: fResp.CreatedAt}, nil
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

	if err := s.storage.UpsertContact(&storage.Contact{UserID: userID, Address: req.Address, TrustLevel: "accepted", FirstSeen: time.Now()}); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to accept contact: %v", err)
	}
	if err := s.storage.MoveMessages(userID, req.Address, "requests", "inbox"); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to move messages to inbox: %v", err)
	}
	return &pb.AcceptContactResponse{Message: "contact accepted"}, nil
}

// GetUserKey implements the federation GetUserKey RPC.
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
	return &pb.GetUserKeyResponse{Address: req.Address, PublicKey: user.PublicKey, ServerSignature: user.ServerSignature, CreatedAt: user.CreatedAt.Unix()}, nil
}

// GetServerInfo implements the GetServerInfo RPC.
func (s *Server) GetServerInfo(ctx context.Context, _ *pb.ServerInfoRequest) (*pb.ServerInfoResponse, error) {
	_ = ctx
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

// DeliverMessage implements the federation DeliverMessage RPC.
func (s *Server) DeliverMessage(ctx context.Context, req *pb.DeliverMessageRequest) (*pb.DeliverMessageResponse, error) {
	_ = ctx
	username, domain, err := federation.ParseAddress(req.Recipient)
	if err != nil {
		return &pb.DeliverMessageResponse{Status: pb.DeliverMessageResponse_REJECTED_NO_SUCH_USER, ErrorMessage: "invalid recipient address"}, nil
	}
	if domain != s.config.Domain {
		return &pb.DeliverMessageResponse{Status: pb.DeliverMessageResponse_REJECTED_NO_SUCH_USER, ErrorMessage: "wrong domain"}, nil
	}

	metadata := &pb.MessageMetadata{Timestamp: req.Metadata.Timestamp, Size: req.Metadata.Size, Subject: req.Metadata.Subject}
	if err := s.deliverLocal(username, req.Sender, req.EncryptedMessage, metadata); err != nil {
		return &pb.DeliverMessageResponse{Status: pb.DeliverMessageResponse_REJECTED_NO_SUCH_USER, ErrorMessage: err.Error()}, nil
	}

	return &pb.DeliverMessageResponse{Status: pb.DeliverMessageResponse_ACCEPTED, MessageId: uuid.New().String(), Timestamp: time.Now().Unix()}, nil
}

func (s *Server) validateToken(token string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", fmt.Errorf("invalid token")
	}
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
	if time.Now().Unix()-timestamp > 3600 {
		return "", fmt.Errorf("token expired")
	}
	return userID, nil
}

func (s *Server) logKeys() {
	log.Printf("Domain: %s", s.config.Domain)
	log.Printf("Server encryption public key: %s", base64.StdEncoding.EncodeToString(s.serverKey.PublicKey))
	log.Printf("Server signing public key: %s", base64.StdEncoding.EncodeToString(s.signKey.PublicKey))
}
