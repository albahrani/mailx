# Protocol Specification - MailX v1.0

## 1. Overview

MailX is a federated messaging protocol designed to replace email with better security and privacy. This document specifies the wire protocol, message formats, and API contracts.

**Protocol Version:** 1.0  
**Status:** Draft  
**Last Updated:** 2026-02-17

## 2. Protocol Stack

```
┌────────────────────────────────┐
│   Application Messages         │
│   (E2EE with libsodium)       │
├────────────────────────────────┤
│   gRPC Services                │
│   (Protocol Buffers)           │
├────────────────────────────────┤
│   TLS 1.3 / mTLS               │
├────────────────────────────────┤
│   HTTP/2                       │
├────────────────────────────────┤
│   TCP                          │
└────────────────────────────────┘
```

## 3. Transport Layer

### 3.1 Client-to-Server Communication

**Protocol:** gRPC over TLS 1.3  
**Port:** 8443 (default, configurable)  
**TLS Requirements:**
- Minimum version: TLS 1.3
- Server presents valid TLS certificate
- Client verifies certificate (standard CA or pinned)
- Forward secrecy required (ECDHE key exchange)

### 3.2 Server-to-Server Communication

**Protocol:** gRPC over mutual TLS (mTLS)  
**Port:** 8443 (default, configurable)  
**mTLS Requirements:**
- Both servers present certificates
- Certificates signed by respective domain keys
- Each server verifies peer's certificate against published domain key
- Certificate subject must match domain name (SAN)

### 3.3 Discovery Endpoints

**DNS Discovery:**
```
_mailx.<domain> TXT "v=mailx1;k=<base64-pubkey>;e=<grpc-endpoint>"
```

**HTTPS Well-Known:**
```
GET https://<domain>/.well-known/mailx-server
Content-Type: application/json

{
  "version": "1.0",
  "domain": "example.com",
  "publicKey": "<base64-encoded-ed25519-public-key>",
  "endpoints": {
    "grpc": "mailx.example.com:8443"
  },
  "created": "2026-01-01T00:00:00Z"
}
```

## 4. Data Formats

### 4.1 Encoding

**Wire Format:** Protocol Buffers (protobuf3)  
**Text Encoding:** UTF-8  
**Binary Encoding:** Base64 for binary data in JSON contexts  
**Timestamps:** RFC 3339 / ISO 8601 format in UTC

### 4.2 Identity Format

**User Address Format:** `username@domain.tld`
- Username: `[a-z0-9._-]+`
- Domain: Valid DNS domain name
- Case-insensitive (normalize to lowercase)

**Example:** `alice@example.com`

### 4.3 Key Format

**Key Type:** Ed25519 (signing and identity)  
**Key Size:** 32 bytes (256 bits)  
**Encoding:** Base64 (standard alphabet, with padding)

**Example:**
```
nQjr5xVp8v+VKlGlbLQfDQjpLZQqy7TYxqGjKlbLQfA=
```

## 5. gRPC Service Definitions

### 5.1 Client API

```protobuf
syntax = "proto3";
package mailx.client.v1;

// Client service for user operations
service ClientService {
  // Account management
  rpc Register(RegisterRequest) returns (RegisterResponse);
  rpc Login(LoginRequest) returns (LoginResponse);
  rpc Logout(LogoutRequest) returns (LogoutResponse);
  
  // Message operations
  rpc SendMessage(SendMessageRequest) returns (SendMessageResponse);
  rpc ListMessages(ListMessagesRequest) returns (ListMessagesResponse);
  rpc GetMessage(GetMessageRequest) returns (GetMessageResponse);
  rpc DeleteMessage(DeleteMessageRequest) returns (DeleteMessageResponse);
  
  // Contact operations
  rpc GetContactKey(GetContactKeyRequest) returns (GetContactKeyResponse);
  rpc UpdateContact(UpdateContactRequest) returns (UpdateContactResponse);
}

message RegisterRequest {
  string username = 1;
  string password_hash = 2;  // bcrypt hash, client-side hashing
  bytes public_key = 3;      // Ed25519 public key
}

message RegisterResponse {
  string user_id = 1;
  bytes server_signature = 2;  // Server's signature over user identity
}

message LoginRequest {
  string username = 1;
  string password = 2;
}

message LoginResponse {
  string access_token = 3;   // JWT token
  int64 expires_at = 4;      // Unix timestamp
}

message SendMessageRequest {
  string access_token = 1;
  repeated string recipients = 2;  // ["bob@example.com"]
  bytes encrypted_message = 3;     // Encrypted message blob
  MessageMetadata metadata = 4;
}

message SendMessageResponse {
  string message_id = 1;
  int64 timestamp = 2;
  repeated DeliveryStatus delivery_statuses = 3;
}

message DeliveryStatus {
  string recipient = 1;
  enum Status {
    PENDING = 0;
    DELIVERED = 1;
    FAILED = 2;
  }
  Status status = 2;
  string error_message = 3;
}

message MessageMetadata {
  int64 timestamp = 1;
  int32 size = 2;
  string subject = 3;  // Unencrypted for now (future: move to encrypted body)
}

message ListMessagesRequest {
  string access_token = 1;
  string folder = 2;  // "inbox", "sent", "requests", "trash"
  int32 limit = 3;
  int32 offset = 4;
}

message ListMessagesResponse {
  repeated MessageSummary messages = 1;
  int32 total_count = 2;
}

message MessageSummary {
  string message_id = 1;
  string sender = 2;
  string subject = 3;
  int64 timestamp = 4;
  int32 size = 5;
  bool read = 6;
}

message GetMessageRequest {
  string access_token = 1;
  string message_id = 2;
}

message GetMessageResponse {
  string message_id = 1;
  string sender = 2;
  bytes encrypted_message = 3;
  MessageMetadata metadata = 4;
}
```

### 5.2 Federation API

```protobuf
syntax = "proto3";
package mailx.federation.v1;

// Federation service for server-to-server communication
service FederationService {
  rpc DeliverMessage(DeliverMessageRequest) returns (DeliverMessageResponse);
  rpc GetServerInfo(ServerInfoRequest) returns (ServerInfoResponse);
  rpc GetUserKey(GetUserKeyRequest) returns (GetUserKeyResponse);
}

message DeliverMessageRequest {
  string sender = 1;           // alice@a.com
  string recipient = 2;        // bob@b.com
  bytes encrypted_message = 3; // E2EE message blob
  MessageMetadata metadata = 4;
  bytes sender_server_signature = 5;  // Signature by sender's server
}

message DeliverMessageResponse {
  enum Status {
    ACCEPTED = 0;
    REJECTED_NO_SUCH_USER = 1;
    REJECTED_QUOTA_EXCEEDED = 2;
    REJECTED_RATE_LIMITED = 3;
    REJECTED_BLOCKED = 4;
  }
  Status status = 1;
  string message_id = 2;
  int64 timestamp = 3;
  string error_message = 4;
}

message ServerInfoRequest {
  string domain = 1;
}

message ServerInfoResponse {
  string domain = 1;
  bytes public_key = 2;  // Domain Ed25519 public key
  string version = 3;    // Protocol version
  ServerCapabilities capabilities = 4;
}

message ServerCapabilities {
  bool supports_e2ee = 1;
  bool supports_key_transparency = 2;
  int32 max_message_size = 3;
}

message GetUserKeyRequest {
  string address = 1;  // alice@example.com
}

message GetUserKeyResponse {
  string address = 1;
  bytes public_key = 2;
  bytes server_signature = 3;
  int64 created_at = 4;
}
```

## 6. Message Format

### 6.1 Encrypted Message Structure

```json
{
  "version": "1.0",
  "messageId": "550e8400-e29b-41d4-a716-446655440000",
  "sender": "alice@a.com",
  "recipients": ["bob@b.com"],
  "timestamp": "2026-02-17T15:30:00Z",
  
  "encryption": {
    "algorithm": "nacl-box",
    "nonce": "<24-byte-base64-nonce>",
    "ciphertext": "<base64-encrypted-payload>"
  },
  
  "signature": {
    "algorithm": "ed25519",
    "publicKey": "<sender-public-key-base64>",
    "signature": "<base64-signature>"
  }
}
```

### 6.2 Plaintext Payload (Before Encryption)

```json
{
  "headers": {
    "subject": "Meeting Tomorrow",
    "contentType": "text/plain",
    "inReplyTo": "<parent-message-id>",
    "references": ["<thread-root-id>"]
  },
  
  "body": "Let's meet at 3pm in the conference room.",
  
  "attachments": [
    {
      "filename": "agenda.pdf",
      "contentType": "application/pdf",
      "size": 12345,
      "data": "<base64-encoded-file-data>"
    }
  ]
}
```

## 7. Cryptographic Operations

### 7.1 Key Generation

**User Key Pair:**
```
(publicKey, privateKey) = crypto_sign_keypair()
// Ed25519, generates 32-byte public key and 64-byte private key
```

**Server Domain Key Pair:**
```
(publicKey, privateKey) = crypto_sign_keypair()
// Ed25519, same as user keys
```

### 7.2 Message Encryption

**Single Recipient (crypto_box):**
```
nonce = random_bytes(24)
ciphertext = crypto_box(
  message: plaintext_json,
  nonce: nonce,
  recipient_public_key: recipient_pubkey,
  sender_private_key: sender_privkey
)
```

**Multiple Recipients (Hybrid):**
```
symmetric_key = random_bytes(32)
nonce = random_bytes(24)
ciphertext = crypto_secretbox(
  message: plaintext_json,
  nonce: nonce,
  key: symmetric_key
)

for each recipient:
  encrypted_key = crypto_box(
    message: symmetric_key,
    nonce: recipient_specific_nonce,
    recipient_public_key: recipient_pubkey,
    sender_private_key: sender_privkey
  )
  key_packets.append({
    recipient: recipient_address,
    encrypted_key: encrypted_key,
    nonce: recipient_specific_nonce
  })
```

### 7.3 Message Signing

```
signature = crypto_sign_detached(
  message: ciphertext,
  private_key: sender_privkey
)
```

### 7.4 Signature Verification

```
valid = crypto_sign_verify_detached(
  signature: signature,
  message: ciphertext,
  public_key: sender_pubkey
)
```

### 7.5 Server Attestation

**Signing User Public Key:**
```
attestation_data = username || "@" || domain || public_key
server_signature = crypto_sign_detached(
  message: attestation_data,
  private_key: server_domain_privkey
)
```

**Verifying Attestation:**
```
attestation_data = username || "@" || domain || public_key
valid = crypto_sign_verify_detached(
  signature: server_signature,
  message: attestation_data,
  public_key: server_domain_pubkey
)
```

## 8. Authentication

### 8.1 Password Authentication

**Registration:**
```
1. Client hashes password with bcrypt (cost 12)
2. Client sends: {username, password_hash, public_key}
3. Server stores password_hash
4. Server signs user's public_key
5. Server returns: {user_id, server_signature}
```

**Login:**
```
1. Client sends: {username, password}
2. Server verifies password against stored hash
3. Server generates JWT token (expires in 1 hour)
4. Server returns: {access_token, expires_at}
```

### 8.2 Token-Based Authentication

**JWT Token Structure:**
```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "alice@example.com",
    "iat": 1708196400,
    "exp": 1708200000,
    "iss": "mailx-server-example.com"
  }
}
```

**Using Token:**
```
Every API call includes: access_token in request
Server validates:
  - Token signature
  - Token not expired
  - User still exists and active
```

### 8.3 mTLS for Federation

**Certificate Generation:**
```
1. Server generates TLS certificate
2. Certificate signed by domain private key
3. Certificate SAN includes domain name
4. Certificate valid for 7 days
5. Auto-renew before expiration
```

**Connection Authentication:**
```
1. Both servers present certificates during TLS handshake
2. Verify certificate signature against domain public key
3. Verify domain public key matches discovered key (DNS/HTTPS)
4. If valid, establish mTLS connection
```

## 9. Federation Protocol

### 9.1 Server Discovery

**Step 1: DNS Lookup**
```
Query: _mailx.example.com TXT
Response: "v=mailx1;k=nQjr5xVp...;e=mailx.example.com:8443"

Parse:
  version = "mailx1"
  public_key_fingerprint = "nQjr5xVp..."
  endpoint = "mailx.example.com:8443"
```

**Step 2: HTTPS Verification**
```
GET https://example.com/.well-known/mailx-server

Response:
{
  "version": "1.0",
  "domain": "example.com",
  "publicKey": "<full-public-key-base64>",
  "endpoints": {
    "grpc": "mailx.example.com:8443"
  },
  "created": "2026-01-01T00:00:00Z"
}

Verify:
  - fingerprint(publicKey) == DNS fingerprint
  - domain matches expected
```

### 9.2 Message Delivery Flow

```
1. User alice@a.com sends message to bob@b.com
   a. Client encrypts message with Bob's public key
   b. Client sends to Server A via ClientService.SendMessage
   
2. Server A processes message
   a. Verify alice is authenticated
   b. Extract recipient domain: "b.com"
   c. Discover Server B endpoint (cache or DNS lookup)
   
3. Server A connects to Server B
   a. Establish mTLS connection
   b. Verify Server B's certificate and domain key
   
4. Server A delivers message
   a. Call FederationService.DeliverMessage
   b. Include sender, recipient, encrypted_message, signature
   
5. Server B processes delivery
   a. Verify sender's server signature
   b. Check recipient exists
   c. Check quotas and rate limits
   d. Store encrypted message
   e. Return ACCEPTED or error
   
6. Server A updates delivery status
   a. Notify client of success/failure
   b. Retry on transient failures
```

### 9.3 Error Handling

**Retry Policy:**
```
Initial retry: 1 minute
Subsequent retries: exponential backoff (2^n minutes)
Max retry interval: 60 minutes
Max attempts: 24 (covers ~24 hours)
After max attempts: move to dead letter queue
```

**Error Codes:**
```
ACCEPTED (0):             Message stored successfully
NO_SUCH_USER (1):         Recipient doesn't exist (no retry)
QUOTA_EXCEEDED (2):       Recipient out of storage (retry later)
RATE_LIMITED (3):         Too many messages (retry later)
BLOCKED (4):              Sender is blocked (no retry)
SERVER_ERROR (5):         Internal error (retry)
TEMPORARILY_UNAVAILABLE (6): Server overloaded (retry)
```

## 10. Rate Limiting

### 10.1 Client Rate Limits

**Per User:**
- Messages sent: 100/hour (burst: 20)
- API requests: 1000/hour (burst: 100)
- Login attempts: 5/hour (account lockout after)

**Enforcement:**
```
Token bucket algorithm
Refill rate: configured limit per hour
Bucket size: burst allowance
Reset: hourly rolling window
```

### 10.2 Federation Rate Limits

**Per Remote Domain:**
- Incoming messages: 1000/hour (burst: 100)
- Connection attempts: 100/hour
- Key lookups: 100/hour

**Enforcement:**
```
Per-domain counters
Sliding window (past 1 hour)
Return RATE_LIMITED status when exceeded
Peer should back off exponentially
```

## 11. Versioning and Compatibility

### 11.1 Protocol Version Negotiation

**Version Field in Requests:**
```
Every request includes protocol version
Client/Server advertise supported versions
Use highest common version
Minimum supported version: 1.0
```

**Backward Compatibility:**
```
Version 1.x: Backward compatible with 1.0
Version 2.x: May break compatibility, negotiation required
Servers must support at least 2 major versions
```

### 11.2 Feature Detection

**ServerCapabilities:**
```
Servers advertise optional features:
  - supports_e2ee: true (required for v1)
  - supports_key_transparency: false (future)
  - max_message_size: 26214400 (25 MB)
  - supported_versions: ["1.0", "1.1"]
```

**Client Adaptation:**
```
Clients query ServerCapabilities
Adapt behavior based on server features
Graceful degradation if feature unavailable
```

## 12. Security Considerations

### 12.1 Mandatory Security Features

- ✅ TLS 1.3 minimum for all connections
- ✅ mTLS for server-to-server
- ✅ Ed25519 signatures on all messages
- ✅ XSalsa20-Poly1305 encryption (libsodium)
- ✅ bcrypt password hashing (cost ≥ 12)
- ✅ JWT tokens with expiration
- ✅ Rate limiting on all APIs

### 12.2 Security Headers

**TLS Configuration:**
```
Min version: TLS 1.3
Cipher suites: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
Forward secrecy: Required (ECDHE)
Certificate validation: Strict
```

**HTTP Headers (Well-Known endpoint):**
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'none'
X-Content-Type-Options: nosniff
```

### 12.3 Input Validation

**Username:**
```
Pattern: ^[a-z0-9._-]{1,64}$
Normalize: lowercase
Block: admin, postmaster, abuse, security (reserved)
```

**Domain:**
```
Valid DNS domain name
Max length: 253 characters
Use punycode for internationalized domains
```

**Message Size:**
```
Max: 25 MB (configurable)
Reject larger messages with error
```

## 13. Test Vectors

### 13.1 Key Generation

```
Seed (hex): 
  0000000000000000000000000000000000000000000000000000000000000000

Public Key (base64):
  MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE...

Private Key: (not shown)
```

### 13.2 Encryption Example

```
Plaintext: "Hello, World!"
Sender Private Key: (test key)
Recipient Public Key: (test key)
Nonce (hex): 000102030405060708090a0b0c0d0e0f1011121314151617

Ciphertext (base64):
  vD7VnC7l9M8K8Vo8FsB4bGqI+JKl8eBg2nYc
```

### 13.3 Signature Example

```
Message: "Test message"
Private Key: (test key)

Signature (base64):
  kX7fN8mJKl4vD...
```

## 14. Conformance

### 14.1 MUST Requirements

Implementations MUST:
- Support protocol version 1.0
- Implement E2EE with libsodium
- Use Ed25519 for signatures
- Enforce TLS 1.3 minimum
- Validate all signatures
- Implement rate limiting
- Support gRPC and Protocol Buffers

### 14.2 SHOULD Requirements

Implementations SHOULD:
- Support DNSSEC for server discovery
- Implement key caching
- Use constant-time crypto operations
- Log security events
- Support key rotation

### 14.3 MAY Requirements

Implementations MAY:
- Support additional encryption algorithms
- Implement key transparency
- Add custom metadata fields
- Extend protocol with optional features

## 15. References

**Cryptography:**
- [NaCl](https://nacl.cr.yp.to/) - Networking and Cryptography library
- [libsodium](https://doc.libsodium.org/) - NaCl fork with better portability
- [RFC 8032](https://tools.ietf.org/html/rfc8032) - Ed25519 signature scheme

**Protocols:**
- [gRPC](https://grpc.io/) - RPC framework
- [Protocol Buffers](https://protobuf.dev/) - Serialization format
- [RFC 8446](https://tools.ietf.org/html/rfc8446) - TLS 1.3

**Standards:**
- [RFC 3339](https://tools.ietf.org/html/rfc3339) - Date and time format
- [RFC 5280](https://tools.ietf.org/html/rfc5280) - X.509 certificates
- [RFC 7519](https://tools.ietf.org/html/rfc7519) - JWT tokens

---

**Document Status:** DRAFT  
**Next Review:** Before Alpha release  
**Feedback:** Open issues on GitHub repository
