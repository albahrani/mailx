package storage

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Storage handles database operations
type Storage struct {
	db *sql.DB
}

// User represents a user account
type User struct {
	ID              string
	Username        string
	Domain          string
	PasswordHash    string
	PublicKey       []byte
	ServerSignature []byte
	CreatedAt       time.Time
	QuotaBytes      int64
}

// Message represents a stored message
type Message struct {
	ID               string
	RecipientUserID  string
	SenderAddress    string
	EncryptedBlob    []byte
	Subject          string
	Timestamp        time.Time
	Size             int32
	Read             bool
	Folder           string // inbox, sent, requests
}

// Contact represents a contact entry
type Contact struct {
	UserID       string
	Address      string
	TrustLevel   string // unknown, accepted, blocked
	FirstSeen    time.Time
}

// New creates a new Storage instance
func New(dbPath string) (*Storage, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	storage := &Storage{db: db}
	if err := storage.initSchema(); err != nil {
		return nil, err
	}

	return storage, nil
}

// Close closes the database connection
func (s *Storage) Close() error {
	return s.db.Close()
}

// initSchema creates the database schema
func (s *Storage) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT NOT NULL,
		domain TEXT NOT NULL,
		password_hash TEXT NOT NULL,
		public_key BLOB NOT NULL,
		server_signature BLOB NOT NULL,
		created_at DATETIME NOT NULL,
		quota_bytes INTEGER NOT NULL DEFAULT 10737418240,
		UNIQUE(username, domain)
	);

	CREATE TABLE IF NOT EXISTS messages (
		id TEXT PRIMARY KEY,
		recipient_user_id TEXT NOT NULL,
		sender_address TEXT NOT NULL,
		encrypted_blob BLOB NOT NULL,
		subject TEXT NOT NULL,
		timestamp DATETIME NOT NULL,
		size INTEGER NOT NULL,
		read BOOLEAN NOT NULL DEFAULT 0,
		folder TEXT NOT NULL DEFAULT 'inbox',
		FOREIGN KEY(recipient_user_id) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS contacts (
		user_id TEXT NOT NULL,
		address TEXT NOT NULL,
		trust_level TEXT NOT NULL DEFAULT 'unknown',
		first_seen DATETIME NOT NULL,
		PRIMARY KEY(user_id, address),
		FOREIGN KEY(user_id) REFERENCES users(id)
	);

	CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_user_id, folder, timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_contacts_user ON contacts(user_id);
	`

	_, err := s.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	return nil
}

// CreateUser creates a new user
func (s *Storage) CreateUser(user *User) error {
	query := `
		INSERT INTO users (id, username, domain, password_hash, public_key, server_signature, created_at, quota_bytes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := s.db.Exec(query, user.ID, user.Username, user.Domain, user.PasswordHash,
		user.PublicKey, user.ServerSignature, user.CreatedAt, user.QuotaBytes)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

// GetUser retrieves a user by username and domain
func (s *Storage) GetUser(username, domain string) (*User, error) {
	query := `
		SELECT id, username, domain, password_hash, public_key, server_signature, created_at, quota_bytes
		FROM users
		WHERE username = ? AND domain = ?
	`
	var user User
	err := s.db.QueryRow(query, username, domain).Scan(
		&user.ID, &user.Username, &user.Domain, &user.PasswordHash,
		&user.PublicKey, &user.ServerSignature, &user.CreatedAt, &user.QuotaBytes,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return &user, nil
}

// GetUserByID retrieves a user by ID
func (s *Storage) GetUserByID(id string) (*User, error) {
	query := `
		SELECT id, username, domain, password_hash, public_key, server_signature, created_at, quota_bytes
		FROM users
		WHERE id = ?
	`
	var user User
	err := s.db.QueryRow(query, id).Scan(
		&user.ID, &user.Username, &user.Domain, &user.PasswordHash,
		&user.PublicKey, &user.ServerSignature, &user.CreatedAt, &user.QuotaBytes,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return &user, nil
}

// CreateMessage stores a new message
func (s *Storage) CreateMessage(msg *Message) error {
	query := `
		INSERT INTO messages (id, recipient_user_id, sender_address, encrypted_blob, subject, timestamp, size, read, folder)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := s.db.Exec(query, msg.ID, msg.RecipientUserID, msg.SenderAddress,
		msg.EncryptedBlob, msg.Subject, msg.Timestamp, msg.Size, msg.Read, msg.Folder)
	if err != nil {
		return fmt.Errorf("failed to create message: %w", err)
	}
	return nil
}

// ListMessages retrieves messages for a user
func (s *Storage) ListMessages(userID, folder string, limit, offset int) ([]*Message, int, error) {
	// Get total count
	countQuery := `SELECT COUNT(*) FROM messages WHERE recipient_user_id = ? AND folder = ?`
	var total int
	err := s.db.QueryRow(countQuery, userID, folder).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count messages: %w", err)
	}

	// Get messages
	query := `
		SELECT id, recipient_user_id, sender_address, encrypted_blob, subject, timestamp, size, read, folder
		FROM messages
		WHERE recipient_user_id = ? AND folder = ?
		ORDER BY timestamp DESC
		LIMIT ? OFFSET ?
	`
	rows, err := s.db.Query(query, userID, folder, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list messages: %w", err)
	}
	defer rows.Close()

	var messages []*Message
	for rows.Next() {
		var msg Message
		err := rows.Scan(&msg.ID, &msg.RecipientUserID, &msg.SenderAddress,
			&msg.EncryptedBlob, &msg.Subject, &msg.Timestamp, &msg.Size, &msg.Read, &msg.Folder)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan message: %w", err)
		}
		messages = append(messages, &msg)
	}

	return messages, total, nil
}

// GetMessage retrieves a specific message
func (s *Storage) GetMessage(messageID, userID string) (*Message, error) {
	query := `
		SELECT id, recipient_user_id, sender_address, encrypted_blob, subject, timestamp, size, read, folder
		FROM messages
		WHERE id = ? AND recipient_user_id = ?
	`
	var msg Message
	err := s.db.QueryRow(query, messageID, userID).Scan(
		&msg.ID, &msg.RecipientUserID, &msg.SenderAddress,
		&msg.EncryptedBlob, &msg.Subject, &msg.Timestamp, &msg.Size, &msg.Read, &msg.Folder,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("message not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get message: %w", err)
	}
	return &msg, nil
}

// UpsertContact creates or updates a contact
func (s *Storage) UpsertContact(contact *Contact) error {
	query := `
		INSERT INTO contacts (user_id, address, trust_level, first_seen)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(user_id, address) DO UPDATE SET trust_level = excluded.trust_level
	`
	_, err := s.db.Exec(query, contact.UserID, contact.Address, contact.TrustLevel, contact.FirstSeen)
	if err != nil {
		return fmt.Errorf("failed to upsert contact: %w", err)
	}
	return nil
}

// GetContact retrieves a contact
func (s *Storage) GetContact(userID, address string) (*Contact, error) {
	query := `
		SELECT user_id, address, trust_level, first_seen
		FROM contacts
		WHERE user_id = ? AND address = ?
	`
	var contact Contact
	err := s.db.QueryRow(query, userID, address).Scan(
		&contact.UserID, &contact.Address, &contact.TrustLevel, &contact.FirstSeen,
	)
	if err == sql.ErrNoRows {
		return nil, nil // Contact not found is not an error
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get contact: %w", err)
	}
	return &contact, nil
}
