package storage

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestStorage(t *testing.T) *Storage {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := New(dbPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestUserCRUD(t *testing.T) {
	s := newTestStorage(t)
	createdAt := time.Unix(1700000000, 0).UTC()

	u := &User{
		ID:              "u1",
		Username:        "alice",
		Domain:          "example.test",
		PasswordHash:    "hash",
		PublicKey:       []byte{1, 2, 3},
		ServerSignature: []byte{4, 5, 6},
		CreatedAt:       createdAt,
		QuotaBytes:      123,
	}
	if err := s.CreateUser(u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	got, err := s.GetUser("alice", "example.test")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.ID != "u1" || got.Username != "alice" || got.Domain != "example.test" {
		t.Fatalf("unexpected user: %+v", *got)
	}
	if got.QuotaBytes != 123 {
		t.Fatalf("quota: got %d want %d", got.QuotaBytes, 123)
	}
	if got.CreatedAt.Unix() != createdAt.Unix() {
		t.Fatalf("created_at: got %d want %d", got.CreatedAt.Unix(), createdAt.Unix())
	}

	got2, err := s.GetUserByID("u1")
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if got2.Username != "alice" {
		t.Fatalf("unexpected user by id: %+v", *got2)
	}
}

func TestGetMessage_NotFound(t *testing.T) {
	s := newTestStorage(t)
	if _, err := s.GetMessage("missing", "u1"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestListMessages_Offset(t *testing.T) {
	s := newTestStorage(t)

	if err := s.CreateUser(&User{
		ID:              "u1",
		Username:        "alice",
		Domain:          "example.test",
		PasswordHash:    "hash",
		PublicKey:       []byte{1},
		ServerSignature: []byte{2},
		CreatedAt:       time.Unix(1700000000, 0).UTC(),
		QuotaBytes:      1,
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	for i := 0; i < 3; i++ {
		id := "m" + string(rune('a'+i))
		if err := s.CreateMessage(&Message{
			ID:              id,
			RecipientUserID: "u1",
			SenderAddress:   "bob@remote.test",
			EncryptedBlob:   []byte("blob"),
			Subject:         "sub",
			Timestamp:       time.Unix(1700000000+int64(i), 0).UTC(),
			Size:            1,
			Read:            false,
			Folder:          "inbox",
		}); err != nil {
			t.Fatalf("CreateMessage: %v", err)
		}
	}

	msgs, total, err := s.ListMessages("u1", "inbox", 2, 1)
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if total != 3 {
		t.Fatalf("total: got %d want %d", total, 3)
	}
	if len(msgs) != 2 {
		t.Fatalf("len: got %d want %d", len(msgs), 2)
	}
}

func TestContacts_UpsertAndGet(t *testing.T) {
	s := newTestStorage(t)

	// Not found is not an error.
	c, err := s.GetContact("u1", "bob@example.test")
	if err != nil {
		t.Fatalf("GetContact: %v", err)
	}
	if c != nil {
		t.Fatalf("expected nil contact")
	}

	firstSeen := time.Unix(1700000000, 0).UTC()
	if err := s.UpsertContact(&Contact{UserID: "u1", Address: "bob@example.test", TrustLevel: "unknown", FirstSeen: firstSeen}); err != nil {
		t.Fatalf("UpsertContact: %v", err)
	}
	if err := s.UpsertContact(&Contact{UserID: "u1", Address: "bob@example.test", TrustLevel: "accepted", FirstSeen: firstSeen}); err != nil {
		t.Fatalf("UpsertContact(update): %v", err)
	}

	got, err := s.GetContact("u1", "bob@example.test")
	if err != nil {
		t.Fatalf("GetContact(after): %v", err)
	}
	if got == nil || got.TrustLevel != "accepted" {
		t.Fatalf("unexpected contact: %+v", got)
	}
}

func TestMessages_ListAndMove(t *testing.T) {
	s := newTestStorage(t)

	// Create a user so FK constraints are satisfied.
	if err := s.CreateUser(&User{
		ID:              "u1",
		Username:        "alice",
		Domain:          "example.test",
		PasswordHash:    "hash",
		PublicKey:       []byte{1},
		ServerSignature: []byte{2},
		CreatedAt:       time.Unix(1700000000, 0).UTC(),
		QuotaBytes:      1,
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Two messages from same sender, one in requests.
	if err := s.CreateMessage(&Message{
		ID:              "m1",
		RecipientUserID: "u1",
		SenderAddress:   "bob@remote.test",
		EncryptedBlob:   []byte("blob1"),
		Subject:         "sub1",
		Timestamp:       time.Unix(1700000002, 0).UTC(),
		Size:            5,
		Read:            false,
		Folder:          "requests",
	}); err != nil {
		t.Fatalf("CreateMessage(m1): %v", err)
	}
	if err := s.CreateMessage(&Message{
		ID:              "m2",
		RecipientUserID: "u1",
		SenderAddress:   "bob@remote.test",
		EncryptedBlob:   []byte("blob2"),
		Subject:         "sub2",
		Timestamp:       time.Unix(1700000003, 0).UTC(),
		Size:            5,
		Read:            false,
		Folder:          "requests",
	}); err != nil {
		t.Fatalf("CreateMessage(m2): %v", err)
	}

	msgs, total, err := s.ListMessages("u1", "requests", 10, 0)
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if total != 2 || len(msgs) != 2 {
		t.Fatalf("unexpected counts: total=%d len=%d", total, len(msgs))
	}
	if msgs[0].ID != "m2" {
		t.Fatalf("expected newest first, got %q", msgs[0].ID)
	}

	if err := s.MoveMessages("u1", "bob@remote.test", "requests", "inbox"); err != nil {
		t.Fatalf("MoveMessages: %v", err)
	}

	msgs2, total2, err := s.ListMessages("u1", "inbox", 10, 0)
	if err != nil {
		t.Fatalf("ListMessages(inbox): %v", err)
	}
	if total2 != 2 || len(msgs2) != 2 {
		t.Fatalf("unexpected inbox counts: total=%d len=%d", total2, len(msgs2))
	}
}
