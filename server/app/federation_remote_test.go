package app

import (
	"context"
	"encoding/base64"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/albahrani/mailx/server/internal/crypto"
	"github.com/albahrani/mailx/server/internal/federation"
	"github.com/albahrani/mailx/server/internal/storage"
	pb "github.com/albahrani/mailx/server/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func newBufconnServerWithDomain(t *testing.T, domain string) (*Server, *grpc.Server, *bufconn.Listener) {
	t.Helper()
	dir := t.TempDir()
	cfg := &Config{
		Domain:         domain,
		GRPCPort:       "0",
		HTTPPort:       "0",
		DatabasePath:   filepath.Join(dir, "test.db"),
		ServerKeyFile:  filepath.Join(dir, "server_key.json"),
		MaxMessageSize: 1024 * 1024,
		DefaultQuota:   1024,
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer(%s): %v", domain, err)
	}

	gs := grpc.NewServer()
	s.RegisterGRPC(gs)
	lis := bufconn.Listen(1024 * 1024)
	go func() { _ = gs.Serve(lis) }()

	t.Cleanup(func() {
		gs.Stop()
		_ = lis.Close()
		_ = s.Close()
	})

	return s, gs, lis
}

func dialBufconnListener(ctx context.Context, lis *bufconn.Listener) (*grpc.ClientConn, error) {
	dialer := func(ctx context.Context, _ string) (net.Conn, error) { return lis.Dial() }
	return grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(dialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
}

func TestRemote_GetContactKey_FetchesAndVerifies(t *testing.T) {
	// A queries for a user hosted on B.
	serverA, _, lisA := newBufconnServerWithDomain(t, "a.test")
	serverB, _, lisB := newBufconnServerWithDomain(t, "b.test")

	// Register user on B.
	bUserKP, _ := crypto.GenerateKeyPair()
	bUserAddr := "bob@b.test"
	createdAt := time.Now().Add(-1 * time.Minute)
	attPayload := federation.KeyAttestationPayload(bUserAddr, bUserKP.PublicKey, createdAt.Unix())
	attSig := serverB.signKey.Sign(attPayload)
	if err := serverB.storage.CreateUser(&storage.User{
		ID:              "u-bob",
		Username:        "bob",
		Domain:          "b.test",
		PasswordHash:    crypto.HashPassword("pw"),
		PublicKey:       bUserKP.PublicKey,
		ServerSignature: attSig,
		CreatedAt:       createdAt,
		QuotaBytes:      1024,
	}); err != nil {
		t.Fatalf("CreateUser(bob@b.test): %v", err)
	}

	// A's discovery should return B's signing key + endpoint.
	serverA.discoveryOverride = map[string]*federation.ServerInfo{
		"b.test": {
			Domain:    "b.test",
			PublicKey: serverB.SigningPublicKey(),
			Endpoint:  "bufnet-b",
			CachedAt:  time.Now(),
			TTL:       time.Hour,
		},
	}

	// A should dial B via bufconn when endpoint matches.
	serverA.federationDial = func(ctx context.Context, endpoint string, _ credentials.TransportCredentials) (*grpc.ClientConn, error) {
		if endpoint != "bufnet-b" {
			return nil, context.Canceled
		}
		return dialBufconnListener(ctx, lisB)
	}

	// Call GetContactKey on A for remote address.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Need a gRPC client to A.
	connA, err := dialBufconnListener(ctx, lisA)
	if err != nil {
		t.Fatalf("dial A: %v", err)
	}
	defer connA.Close()
	clientA := pb.NewClientServiceClient(connA)

	// Create a local user on A and get a token to pass auth.
	aUserKP, _ := crypto.GenerateKeyPair()
	if _, err := clientA.Register(ctx, &pb.RegisterRequest{Username: "alice", Password: "pw", PublicKey: aUserKP.PublicKey}); err != nil {
		t.Fatalf("Register(alice@a.test): %v", err)
	}
	login, err := clientA.Login(ctx, &pb.LoginRequest{Username: "alice", Password: "pw"})
	if err != nil {
		t.Fatalf("Login(alice@a.test): %v", err)
	}

	resp, err := clientA.GetContactKey(ctx, &pb.GetContactKeyRequest{AccessToken: login.AccessToken, Address: bUserAddr})
	if err != nil {
		t.Fatalf("GetContactKey(remote): %v", err)
	}
	if resp.Address != bUserAddr {
		t.Fatalf("address mismatch")
	}
	if base64.StdEncoding.EncodeToString(resp.PublicKey) != base64.StdEncoding.EncodeToString(bUserKP.PublicKey) {
		t.Fatalf("public key mismatch")
	}
}

func TestRemote_SendMessage_DeliversViaFederation(t *testing.T) {
	// Sender on A sends to recipient on B; A uses federation DeliverMessage.
	serverA, _, lisA := newBufconnServerWithDomain(t, "a.test")
	serverB, _, lisB := newBufconnServerWithDomain(t, "b.test")

	// Recipient on B.
	bUserKP, _ := crypto.GenerateKeyPair()
	if _, err := func() (*pb.RegisterResponse, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		connB, err := dialBufconnListener(ctx, lisB)
		if err != nil {
			return nil, err
		}
		defer connB.Close()
		clientB := pb.NewClientServiceClient(connB)
		return clientB.Register(ctx, &pb.RegisterRequest{Username: "bob", Password: "pw", PublicKey: bUserKP.PublicKey})
	}(); err != nil {
		t.Fatalf("Register(bob@b.test): %v", err)
	}

	// Wire discovery + dialer on A.
	serverA.discoveryOverride = map[string]*federation.ServerInfo{
		"b.test": {
			Domain:    "b.test",
			PublicKey: serverB.SigningPublicKey(),
			Endpoint:  "bufnet-b",
			CachedAt:  time.Now(),
			TTL:       time.Hour,
		},
	}
	serverA.federationDial = func(ctx context.Context, endpoint string, _ credentials.TransportCredentials) (*grpc.ClientConn, error) {
		if endpoint != "bufnet-b" {
			return nil, context.Canceled
		}
		return dialBufconnListener(ctx, lisB)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connA, err := dialBufconnListener(ctx, lisA)
	if err != nil {
		t.Fatalf("dial A: %v", err)
	}
	defer connA.Close()
	clientA := pb.NewClientServiceClient(connA)

	// Sender user on A.
	aUserKP, _ := crypto.GenerateKeyPair()
	if _, err := clientA.Register(ctx, &pb.RegisterRequest{Username: "alice", Password: "pw", PublicKey: aUserKP.PublicKey}); err != nil {
		t.Fatalf("Register(alice@a.test): %v", err)
	}
	loginA, err := clientA.Login(ctx, &pb.LoginRequest{Username: "alice", Password: "pw"})
	if err != nil {
		t.Fatalf("Login(alice@a.test): %v", err)
	}

	// Send remote.
	blob := []byte("cipher")
	if _, err := clientA.SendMessage(ctx, &pb.SendMessageRequest{
		AccessToken:      loginA.AccessToken,
		Recipients:       []string{"bob@b.test"},
		EncryptedMessage: blob,
		Metadata:         &pb.MessageMetadata{Timestamp: time.Now().Unix(), Size: int32(len(blob)), Subject: "hi"},
	}); err != nil {
		t.Fatalf("SendMessage(remote): %v", err)
	}

	// Verify on B that message is in requests.
	connB, err := dialBufconnListener(ctx, lisB)
	if err != nil {
		t.Fatalf("dial B: %v", err)
	}
	defer connB.Close()
	clientB := pb.NewClientServiceClient(connB)
	loginB, err := clientB.Login(ctx, &pb.LoginRequest{Username: "bob", Password: "pw"})
	if err != nil {
		t.Fatalf("Login(bob@b.test): %v", err)
	}
	list, err := clientB.ListMessages(ctx, &pb.ListMessagesRequest{AccessToken: loginB.AccessToken, Folder: "requests", Limit: 10})
	if err != nil {
		t.Fatalf("ListMessages(B/requests): %v", err)
	}
	if len(list.Messages) != 1 {
		t.Fatalf("expected 1 delivered message, got %d", len(list.Messages))
	}
}
