# Server PRD - MailX Secure Email Replacement

## Overview
The MailX server is a federated messaging server designed to replace traditional email with a secure, privacy-focused, self-hostable alternative. Each server instance manages identities for its domain and federates with other MailX servers to deliver messages.

## 1. Identity Management

### 1.1 Domain-Based Identity
- **Requirement**: Server acts as the root of trust for its domain (e.g., `user@example.com`)
- **Domain Keys**: Each server generates and maintains a domain key pair (Ed25519)
  - Public key published via DNS TXT record or `.well-known` endpoint
  - Private key stored securely (encrypted at rest)
- **User Accounts**: Users register on their domain server
  - Username validation (lowercase alphanumeric + basic punctuation)
  - No email verification required for local accounts
  - Support for admin-created accounts

### 1.2 Key Management
- **Server Attestation**: Server signs user public keys to create binding
  - User identity = username@domain + user_public_key + server_signature
- **Key Rotation**: Support for key rotation with grace period
  - Old keys marked as deprecated, new keys announced
  - 30-day overlap period for migration
- **Key Storage**: Store user keys in database
  - Key history for auditing
  - Key transparency log (future milestone)

## 2. Federation

### 2.1 Server Discovery
- **DNS-based Discovery**: Query TXT records for `_mailx.<domain>`
  - Record contains server endpoints and public key fingerprint
- **Well-Known Endpoint**: `https://<domain>/.well-known/mailx-server`
  - Returns JSON with server metadata, public key, and endpoints
- **Fallback**: Direct configuration for testing/demo

### 2.2 Inter-Server Communication
- **Protocol**: gRPC over mTLS for server-to-server communication
  - TLS 1.3 minimum
  - Certificate verification against domain keys
- **Authentication**: Mutual authentication using domain keys
  - Each server presents certificate signed by domain key
  - Verify peer domain key against discovery mechanism
- **Rate Limiting**: Per-domain rate limits to prevent abuse
  - Default: 100 messages/minute per remote domain
  - Configurable per peer

### 2.3 Message Routing
- **Address Resolution**: Parse recipient address to extract domain
- **Delivery Protocol**: 
  - Lookup remote server endpoint
  - Establish mTLS connection
  - Submit encrypted message blob
  - Receive delivery acknowledgment
- **Retry Logic**: Exponential backoff for failed deliveries
  - Initial retry: 1 minute
  - Max retry interval: 1 hour
  - Max attempts: 24 (covers 24 hours)
  - Dead letter queue for permanently failed messages

## 3. Anti-Abuse and DoS Protection

### 3.1 Rate Limiting
- **Inbound Messages**: Limit messages per remote domain
  - Default: 1000 messages/hour per domain
  - Burst allowance: 100 messages
- **Outbound Messages**: Limit messages per local user
  - Default: 100 messages/hour per user
  - Configurable per account
- **Connection Limits**: Max concurrent connections per peer
  - Default: 10 connections per remote domain

### 3.2 Spam Prevention
- **First Contact Protocol**: Recipients must accept first message from new sender
  - Messages from unknown senders go to "requests" folder
  - Explicit accept/reject action required
  - Once accepted, future messages delivered normally
- **Block List**: Users can block sender domains or individual addresses
  - Blocked messages rejected at delivery time
- **Server Block List**: Admin-level blocking of abusive domains
  - Shared block list support (optional, configurable)

### 3.3 Resource Protection
- **Message Size Limits**: Default max message size: 25 MB
- **Storage Quotas**: Per-user storage quota (default: 10 GB)
  - Configurable per account
  - Reject new messages when quota exceeded
- **CPU Limits**: Request timeout and processing limits
  - gRPC request timeout: 30 seconds
  - Crypto operations timeout: 5 seconds

## 4. Storage

### 4.1 Database Schema
- **Users Table**: User accounts, keys, quotas
  - user_id, username, public_key, server_signature, created_at, quota_bytes
- **Messages Table**: Encrypted message blobs
  - message_id, recipient_user_id, sender_address, encrypted_blob, metadata, received_at
- **Contacts Table**: Contact list and trust status
  - user_id, contact_address, trust_level (unknown, requested, accepted, blocked), first_seen
- **Federation Cache**: Cache of discovered servers
  - domain, endpoints, public_key, last_verified, ttl

### 4.2 Database Technology
- **Primary**: SQLite for single-server deployments
  - Simple, embedded, no external dependencies
  - Sufficient for most self-hosting scenarios
- **Optional**: PostgreSQL for high-availability deployments
  - Support for clustering and replication
  - Better concurrent write performance

### 4.3 Message Storage
- **Encrypted at Rest**: All message blobs encrypted with server key
  - Additional layer beyond E2EE (defense in depth)
  - Server key derived from configuration secret
- **Retention Policy**: Configurable per-user or server-wide
  - Default: No automatic deletion
  - Support for auto-deletion after N days

## 5. Mailbox Semantics

### 5.1 Folder Structure
- **Inbox**: Accepted messages from known contacts
- **Requests**: First messages from unknown senders (pending accept/reject)
- **Sent**: Messages sent by user
- **Archive**: User-archived messages
- **Trash**: Soft-deleted messages (auto-purge after 30 days)

### 5.2 Message Operations
- **Receive**: Accept message from remote server
  - Verify sender domain signature
  - Check recipient exists and has quota
  - Store encrypted blob
  - Update contact trust if needed
- **Send**: User submits message for delivery
  - Encrypt message with recipient's public key
  - Route to appropriate server
  - Store in sent folder
- **Search**: Full-text search on message metadata
  - Subject, sender, date range
  - Body search requires client-side decryption
- **Sync**: Multi-device sync protocol
  - Version-based conflict resolution
  - Incremental sync support

## 6. Admin Operations

### 6.1 User Management
- **Create Account**: Admin can create accounts with initial quota
- **Suspend Account**: Temporarily disable login and message delivery
- **Delete Account**: Permanently remove account and messages
  - Grace period for data export
- **Quota Management**: Adjust per-user quotas

### 6.2 Server Configuration
- **Domain Setup**: Configure domain, keys, and endpoints
- **Federation Settings**: Configure rate limits, block lists
- **Storage Settings**: Configure quotas, retention policies
- **Security Settings**: TLS configuration, key rotation schedule

### 6.3 Monitoring & Alerts
- **Health Checks**: Service status, database connectivity
- **Metrics**: Message throughput, storage usage, federation status
- **Alerts**: Quota exceeded, failed deliveries, security events

## 7. Observability

### 7.1 Logging
- **Structured Logging**: JSON-formatted logs with timestamps
- **Log Levels**: DEBUG, INFO, WARN, ERROR
- **Sensitive Data**: Never log message content or keys
- **Log Retention**: Configurable, default 30 days

### 7.2 Metrics
- **Prometheus Integration**: Export metrics in Prometheus format
  - Message counts (sent, received, failed)
  - Storage usage (total, per-user)
  - Federation stats (peers, connections, errors)
  - Performance metrics (latency, throughput)

### 7.3 Tracing
- **OpenTelemetry Support**: Distributed tracing for request flows
  - Trace message delivery across servers
  - Performance profiling

## 8. Security Requirements

### 8.1 Authentication
- **User Authentication**: Password-based with rate limiting
  - bcrypt password hashing (cost 12)
  - Max 5 failed attempts per hour
  - Optional 2FA support (TOTP)
- **Server Authentication**: mTLS for federation
  - Verify peer certificates against domain keys

### 8.2 Authorization
- **User Isolation**: Users can only access their own messages
- **Admin Permissions**: Separate admin role for management operations
- **API Access**: Token-based authentication for client APIs
  - JWT tokens with expiration
  - Refresh token mechanism

### 8.3 Data Protection
- **Encryption at Rest**: Server-level encryption for database
- **TLS Everywhere**: All network communication over TLS 1.3
- **Key Security**: Domain keys stored in encrypted keystore
  - Derive encryption key from server secret
  - Support for HSM/TPM (future)

## 9. API Specification

### 9.1 Client API (gRPC)
- **AccountService**: Login, register, manage account
- **MessageService**: Send, receive, search, delete messages
- **ContactService**: Manage contacts, trust levels

### 9.2 Federation API (gRPC)
- **DeliveryService**: Deliver messages between servers
- **DiscoveryService**: Server metadata and key exchange

### 9.3 Admin API (gRPC)
- **UserManagement**: Create, suspend, delete users
- **ServerManagement**: Configure server settings
- **MonitoringService**: Health checks, metrics

## 10. Deployment

### 10.1 Requirements
- **OS**: Linux (Ubuntu 20.04+, Debian 11+, Alpine)
- **CPU**: 1 core minimum, 2+ recommended
- **RAM**: 512 MB minimum, 2 GB recommended
- **Storage**: 10 GB minimum + user data
- **Network**: Static IP or domain with DNS control

### 10.2 Installation
- **Binary Distribution**: Single static binary
- **Docker**: Official Docker image
- **Configuration**: Single YAML or TOML file
  - Environment variable overrides

### 10.3 Backup & Recovery
- **Database Backup**: Regular SQLite backup or PostgreSQL dump
- **Key Backup**: Secure backup of domain keys (essential)
- **Disaster Recovery**: Restore from backup, re-announce domain key

## 11. Testing Requirements

### 11.1 Unit Tests
- Identity management functions
- Crypto operations
- Message routing logic
- Storage operations

### 11.2 Integration Tests
- Server-to-server federation
- Message delivery end-to-end
- Rate limiting and abuse prevention

### 11.3 Security Tests
- TLS configuration validation
- Authentication/authorization bypass attempts
- Rate limit enforcement
- Quota enforcement

## 12. Success Metrics

- **Reliability**: 99.9% uptime for server availability
- **Performance**: Sub-second message delivery to local users
- **Federation**: Sub-5-second delivery to remote servers
- **Resource Usage**: < 100 MB RAM for idle server with 100 users
- **Security**: Zero critical vulnerabilities in security audit

## 13. Future Enhancements

- Key transparency log with gossip protocol
- Group messaging support
- Large file attachments with chunking
- Mobile push notifications via bridge service
- Web client with WASM crypto
- Federation statistics and reputation system
