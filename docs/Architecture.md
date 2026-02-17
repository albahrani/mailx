# Architecture - MailX Secure Email Replacement

## Overview
MailX is a federated, end-to-end encrypted messaging system designed to replace traditional email with a more secure, privacy-focused alternative. This document describes the architecture, protocols, and design decisions.

## 1. System Architecture

### 1.1 Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    MailX Ecosystem                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────┐         ┌──────────┐         ┌──────────┐   │
│  │ Client A │◄───────►│ Server A │◄───────►│ Server B │   │
│  │ alice@a  │         │  (a.com) │         │  (b.com) │   │
│  └──────────┘         └──────────┘         └────▲─────┘   │
│                             │                    │         │
│                             │                    │         │
│                       ┌─────▼─────┐         ┌────▼─────┐  │
│                       │  Storage  │         │ Client B │  │
│                       │ (SQLite)  │         │  bob@b   │  │
│                       └───────────┘         └──────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 Core Components

1. **MailX Server**: Federated message routing and storage server
   - Manages domain identity and keys
   - Routes messages between users and servers
   - Stores encrypted message blobs
   - Provides client API for message access

2. **MailX Client**: User-facing application
   - Local key management
   - End-to-end encryption/decryption
   - Message composition and reading
   - Contact management

3. **Key Directory**: Distributed key discovery
   - DNS-based server discovery
   - Server-attested user keys
   - Optional key transparency log (future)

## 2. Identity Model

### 2.1 Domain as Root of Trust

Each MailX deployment is anchored to a DNS domain. The domain owner controls the root identity for all users under that domain.

**Identity Hierarchy:**
```
DNS Domain (example.com)
    └─ Server Key (Ed25519)
        └─ User Keys (Ed25519)
            └─ Device Keys (Ed25519) [optional for multi-device]
```

### 2.2 Domain Keys

**Generation:**
- Server generates Ed25519 key pair on first initialization
- Private key stored encrypted at rest
- Public key published via DNS and HTTPS

**Publication:**
```
# DNS TXT Record
_mailx.example.com. IN TXT "v=mailx1;k=<base64-encoded-public-key>;e=https://mailx.example.com:8443"

# HTTPS Well-Known Endpoint
GET https://example.com/.well-known/mailx-server
{
  "version": "1.0",
  "domain": "example.com",
  "publicKey": "<base64-encoded-public-key>",
  "endpoints": {
    "grpc": "mailx.example.com:8443",
    "http": "https://mailx.example.com:8080"
  },
  "created": "2026-01-01T00:00:00Z",
  "expiresAt": null
}
```

### 2.3 Server Attestation

When a user registers, the server attests to their public key:

**Attestation Structure:**
```
UserIdentity {
    username: "alice"
    domain: "example.com"
    publicKey: <user-ed25519-public-key>
    serverSignature: <signature over (username || domain || publicKey)>
    createdAt: timestamp
}
```

**Verification Process:**
1. Client receives UserIdentity from server
2. Fetch server public key via DNS/HTTPS
3. Verify `serverSignature` using server public key
4. Accept user public key if signature valid

### 2.4 User Keys

**Key Management:**
- Each user generates Ed25519 key pair on account creation
- Private key stored in client device (never shared)
- Public key registered with server
- Server signs public key to create binding

**Key Rotation:**
- User generates new key pair
- Register new key with server (requires authentication)
- Server publishes both keys with overlap period
- Old key marked as "deprecated" but still valid
- After grace period, old key revoked

### 2.5 Device Keys (Multi-Device)

For multi-device support, each device has its own key pair:

**Device Key Structure:**
```
DeviceKey {
    deviceId: uuid
    deviceName: "Alice's Phone"
    publicKey: <device-ed25519-public-key>
    userSignature: <user-key-signature>
    createdAt: timestamp
}
```

**Message Encryption for Multiple Devices:**
- Sender encrypts message once with symmetric key
- Symmetric key encrypted separately for each recipient device
- All encrypted key packets included in message envelope

## 3. Federation Protocol

### 3.1 Server Discovery

**DNS-Based Discovery:**
```
1. Extract domain from recipient address (bob@example.com → example.com)
2. Query DNS TXT record: _mailx.example.com
3. Parse server endpoint and public key fingerprint
4. Fetch full server metadata via HTTPS
5. Verify public key matches DNS fingerprint
6. Cache result with TTL
```

**Fallback Mechanisms:**
- Static configuration file for testing
- Manual server entry
- Gossip protocol for discovering peers (future)

### 3.2 Mutual TLS (mTLS)

All server-to-server communication uses mTLS:

**Certificate Requirements:**
- Each server generates TLS certificate signed by domain key
- Certificate contains domain name in Subject Alternative Name (SAN)
- Short-lived certificates (7 days) auto-renewed

**Connection Establishment:**
```
1. Server A initiates TLS connection to Server B
2. Server B presents certificate signed by its domain key
3. Server A verifies:
   a. Certificate signed by Server B's domain key
   b. Domain key matches discovered public key
   c. Certificate not expired
4. Server B verifies Server A's certificate (mutual)
5. Establish encrypted channel
```

### 3.3 Peer Authorization

After mTLS handshake, additional authorization:

**Challenge-Response:**
```
1. Server A sends challenge: random nonce
2. Server B signs nonce with domain private key
3. Server A verifies signature with Server B's public key
4. Connection authorized
```

### 3.4 Message Delivery Protocol

**gRPC Service Definition:**
```protobuf
service DeliveryService {
  rpc DeliverMessage(DeliveryRequest) returns (DeliveryResponse);
  rpc GetServerInfo(ServerInfoRequest) returns (ServerInfo);
}

message DeliveryRequest {
  string sender = 1;          // alice@a.com
  string recipient = 2;       // bob@b.com
  bytes encrypted_blob = 3;   // E2EE message
  bytes metadata = 4;         // Minimal metadata (timestamp, size)
  bytes sender_signature = 5; // Signature over blob by sender's server
}

message DeliveryResponse {
  enum Status {
    ACCEPTED = 0;
    REJECTED_NO_SUCH_USER = 1;
    REJECTED_QUOTA_EXCEEDED = 2;
    REJECTED_RATE_LIMITED = 3;
    REJECTED_BLOCKED = 4;
  }
  Status status = 1;
  string message_id = 2;      // Server-assigned ID
  int64 timestamp = 3;        // Server received timestamp
}
```

**Delivery Flow:**
```
1. Client encrypts message with recipient's public key
2. Client sends to local server via Client API
3. Server A validates user authentication
4. Server A signs encrypted blob with domain key
5. Server A discovers Server B via DNS
6. Server A establishes mTLS connection to Server B
7. Server A calls DeliverMessage RPC
8. Server B verifies:
   a. Recipient exists
   b. Sender not blocked
   c. Quota available
   d. Rate limits not exceeded
9. Server B stores encrypted blob
10. Server B returns ACCEPTED or error
11. Server A notifies client of delivery status
```

## 4. End-to-End Encryption (E2EE)

### 4.1 Cryptographic Primitives

**Library**: libsodium (NaCl)
- **Key Exchange**: X25519 (Curve25519 ECDH)
- **Signatures**: Ed25519
- **Encryption**: XSalsa20-Poly1305 (authenticated encryption)
- **Hashing**: BLAKE2b

### 4.2 Message Encryption

**Format:**
```
EncryptedMessage {
  version: 1
  sender: "alice@a.com"
  recipient: "bob@b.com"
  
  // Encrypted with recipient's public key
  encryptedPayload: {
    nonce: <24-byte random nonce>
    ciphertext: <encrypted JSON payload>
    tag: <authentication tag>
  }
  
  // Signature over (sender || recipient || encryptedPayload)
  senderSignature: <ed25519 signature>
}

Payload (before encryption) {
  subject: "Meeting Tomorrow"
  body: "Let's meet at 3pm"
  timestamp: "2026-02-17T15:00:00Z"
  attachments: [...]
  headers: {...}
}
```

**Encryption Process:**
```
1. Client generates random nonce (24 bytes)
2. Client serializes payload to JSON
3. Client encrypts payload:
   encryptedPayload = crypto_box(
     message: payload,
     nonce: nonce,
     recipientPublicKey: bob.publicKey,
     senderPrivateKey: alice.privateKey
   )
4. Client signs encrypted payload with sender's private key
5. Client sends EncryptedMessage to server
```

**Decryption Process:**
```
1. Client receives EncryptedMessage
2. Verify sender signature using sender's public key
3. Decrypt payload:
   payload = crypto_box_open(
     ciphertext: encryptedPayload,
     nonce: nonce,
     senderPublicKey: alice.publicKey,
     recipientPrivateKey: bob.privateKey
   )
4. Parse JSON payload
5. Display message to user
```

### 4.3 Multi-Recipient Messages

For messages to multiple recipients (Cc, Bcc):

**Hybrid Encryption:**
```
1. Generate random symmetric key (256-bit)
2. Encrypt payload with symmetric key (XSalsa20-Poly1305)
3. For each recipient:
   a. Encrypt symmetric key with recipient's public key
   b. Create KeyPacket { recipientId, encryptedKey }
4. Message structure:
   {
     encryptedPayload: <payload encrypted with symmetric key>
     keyPackets: [KeyPacket1, KeyPacket2, ...]
     senderSignature: <signature>
   }
```

### 4.4 Forward Secrecy (Future)

Implement Double Ratchet algorithm (Signal Protocol):
- Ephemeral keys for each message
- Automatic key rotation
- Break-in recovery

## 5. Key Transparency

### 5.1 Goals

- Detect server-side key substitution attacks
- Allow users to audit key history
- Enable public verification of key bindings

### 5.2 Architecture (Future Implementation)

**Merkle Tree Log:**
```
- Each server maintains append-only log of key operations
- Operations: key registration, key rotation, key revocation
- Log entries signed by server
- Merkle tree for efficient proofs
- Gossip protocol for cross-server verification
```

**Verification Process:**
```
1. Client fetches user's public key from server
2. Server provides:
   a. Public key
   b. Merkle proof of inclusion in log
   c. Signed tree head
3. Client verifies:
   a. Merkle proof valid
   b. Tree head signature valid
   c. Cross-check with other servers (gossip)
4. Alerts if inconsistency detected
```

## 6. Anti-Enumeration Design

### 6.1 User Enumeration Prevention

**Challenge**: Prevent attackers from enumerating valid users

**Solution**:
- Public key lookups require authentication
- Rate limit key directory queries
- Constant-time responses (success and failure indistinguishable)
- Optional: Bloom filter for existence checks without revealing full list

### 6.2 Delivery Privacy

**Challenge**: Hide recipient existence from sending server

**Current Approach** (Demo):
- Recipient existence revealed during delivery
- Server returns error if user doesn't exist

**Future Improvement**:
- Private Information Retrieval (PIR) for key lookup
- Onion routing for delivery (mix network)
- Dummy traffic to hide communication patterns

## 7. Threat Model

### 7.1 Adversary Capabilities

**In-Scope Threats:**

1. **Malicious Server Operator**
   - Can read message metadata (sender, recipient, timestamp, size)
   - Can attempt to impersonate users by substituting keys
   - Can delay or drop messages
   - Cannot read message content (E2EE)
   - Mitigations: Key transparency, client-side signature verification

2. **Network Attacker**
   - Can observe network traffic (metadata)
   - Can perform timing correlation attacks
   - Cannot decrypt TLS traffic (forward secrecy)
   - Cannot modify messages (authenticated encryption)
   - Mitigations: mTLS, rate limiting

3. **Compromised Server**
   - Can access stored encrypted messages
   - Can access server private keys
   - Cannot decrypt user messages (E2EE with user keys)
   - Cannot forge user signatures
   - Mitigations: Encryption at rest, key separation

4. **Malicious Client**
   - Can spam other users
   - Can enumerate users on same server
   - Cannot impersonate other users (signature required)
   - Mitigations: Rate limiting, first-contact protocol

### 7.2 Out-of-Scope Threats

- **State-level adversaries**: No defense against targeted attacks with unlimited resources
- **Endpoint compromise**: If user's device compromised, all security guarantees void
- **Metadata analysis**: Traffic analysis and timing attacks partially out of scope
- **Denial of Service**: Can be mitigated but not fully prevented

### 7.3 Security Assumptions

**We Assume:**
1. DNS infrastructure is not globally compromised (use DNSSEC where available)
2. TLS certificate authorities are not systematically malicious
3. Cryptographic primitives (Ed25519, XSalsa20) are secure
4. User devices are not compromised
5. Server operators follow protocol correctly (or key transparency catches deviations)

**We Do NOT Assume:**
1. Server operators are honest (key transparency addresses this)
2. Network is private (use encryption everywhere)
3. Servers are always available (design for intermittent connectivity)
4. All users are good actors (anti-abuse mechanisms required)

### 7.4 Attack Scenarios & Mitigations

| Attack | Impact | Mitigation |
|--------|--------|------------|
| Server key substitution | Impersonation | Key transparency log, client verification |
| MITM on federation | Message interception | mTLS with domain key verification |
| Message replay | Duplicate delivery | Nonce-based deduplication, timestamps |
| Spam/DoS | Resource exhaustion | Rate limiting, first-contact protocol, quotas |
| Metadata leakage | Traffic analysis | TLS everywhere, timing obfuscation (future) |
| Server database breach | Encrypted data exposed | Encryption at rest, forward secrecy (future) |
| Compromised server key | Domain impersonation | Key rotation, key transparency |
| User key compromise | Account takeover | Key revocation, re-encryption |

## 8. Governance and Trust Model

### 8.1 Decentralization Principles

**Core Tenets:**
1. **No Central Authority**: No single entity controls the network
2. **Domain Sovereignty**: Each domain controls its own identity
3. **User Control**: Users choose their server, can migrate
4. **Open Protocol**: Publicly documented, no proprietary extensions
5. **Interoperability**: Multiple client and server implementations

### 8.2 Avoiding Big-Tech Dependency

**Design Decisions:**
- **No Required Cloud Services**: Fully self-hostable
- **No App Store Lock-In**: Distribute via open channels (F-Droid, GitHub, self-hosted)
- **No Centralized Directory**: DNS-based discovery, no central registry
- **No Mandatory CA**: Domain keys as root of trust, optional CA certificates
- **No Phone Number**: Username-based identity, no phone verification

### 8.3 State Resistance

**Censorship Resistance:**
- **Federation**: Blocking one server doesn't affect others
- **Multiple Routes**: Messages can route through friendly servers (future)
- **Tor Support**: Run servers as Tor hidden services (future)

**Anti-Surveillance:**
- **E2EE by Default**: Even server operator cannot read messages
- **Minimal Metadata**: Subject encrypted in body (future)
- **Mix Network**: Hide communication patterns (future)

**Legal Compliance:**
- Server operators may be compelled to comply with local laws
- E2EE limits what can be exposed to authorities
- Users can choose servers in jurisdictions with strong privacy laws
- Warrant canary support (optional server feature)

### 8.4 Trust Anchors

**Bootstrap Trust:**
- **DNS**: Initial trust anchor for domain discovery
  - Use DNSSEC where available
  - Option to pin server keys manually
- **Out-of-Band Verification**: Users can verify contact keys via side channel
  - QR codes, phone calls, in-person meetings
- **Web of Trust**: Future feature for key endorsements
  - Trust contacts vouched for by trusted friends

**Trust Tiers:**
1. **Implicit Trust**: Server-attested keys (TOFU)
2. **Verified Trust**: Manually verified fingerprints
3. **Endorsed Trust**: Keys endorsed by trusted contacts (future)

### 8.5 Governance Model

**Protocol Evolution:**
- **RFC-Style Process**: Propose, discuss, implement
- **Versioning**: Protocol version negotiation
- **Extensions**: Optional extensions that don't break compatibility
- **Reference Implementation**: Open-source server and client
- **Community Governance**: Decisions made by implementers and users

**Server Policies:**
- Each server sets its own policies (rate limits, quotas, retention)
- Policies published in server metadata
- Users choose servers aligned with their preferences

## 9. Protocol Overview

### 9.1 Protocol Stack

```
┌──────────────────────────────────┐
│     Application Protocol         │
│  (Message format, E2EE crypto)   │
├──────────────────────────────────┤
│         gRPC API                 │
│  (Client-Server, Server-Server)  │
├──────────────────────────────────┤
│           TLS 1.3                │
│    (mTLS for federation)         │
├──────────────────────────────────┤
│         TCP / HTTP/2             │
└──────────────────────────────────┘
```

### 9.2 Wire Format

**gRPC Protocol Buffers** for all APIs:
- Client ↔ Server: gRPC over TLS
- Server ↔ Server: gRPC over mTLS
- Efficient binary encoding
- Strong typing and versioning
- Cross-language support

### 9.3 Message Format

See section 4.2 for encryption details.

**Headers:**
```
{
  "version": "1.0",
  "messageId": "<uuid>",
  "from": "alice@a.com",
  "to": ["bob@b.com"],
  "cc": [],
  "bcc": [],
  "timestamp": "2026-02-17T15:00:00Z",
  "inReplyTo": "<parent-message-id>",
  "references": ["<thread-root-id>"]
}
```

**Body:**
```
{
  "subject": "Meeting Tomorrow",
  "contentType": "text/plain",
  "body": "Let's meet at 3pm",
  "attachments": [
    {
      "filename": "agenda.pdf",
      "contentType": "application/pdf",
      "size": 12345,
      "encryptedData": "<base64>"
    }
  ]
}
```

## 10. Performance Considerations

### 10.1 Scalability

**Server Capacity:**
- Single server: 1000-10000 users (depends on hardware)
- Horizontal scaling: Multiple servers per domain (future)
- Database sharding: Split users across databases

**Message Throughput:**
- Target: 1000 messages/second per server
- Bottleneck: Database writes
- Optimization: Batch inserts, write-ahead log

### 10.2 Latency

**Message Delivery:**
- Local delivery: < 100ms
- Remote delivery: < 1 second (plus network latency)
- Crypto operations: < 10ms

**Client Operations:**
- Message decrypt: < 50ms
- Search: < 200ms
- Sync: < 1 second for 100 new messages

### 10.3 Resource Usage

**Server:**
- RAM: 100 MB baseline + 1 MB per active user
- CPU: Minimal at rest, spikes during crypto operations
- Disk: User data + 10% overhead for indexes
- Network: Proportional to message volume

**Client:**
- RAM: 100 MB baseline + cached messages
- CPU: Minimal except during encryption/decryption
- Disk: Message cache + search index
- Network: Download only new messages (incremental)

## 11. Migration and Compatibility

### 11.1 Email Migration

**Import from IMAP:**
- Client can import messages from existing email accounts
- Decrypt if possible (PGP/S/MIME)
- Re-encrypt with MailX keys
- Preserve metadata (sender, date, subject)

**Gradual Adoption:**
- Users can keep email account active during transition
- Clients can check both MailX and email
- Forward email to MailX gateway (bridge service, future)

### 11.2 Protocol Versioning

**Version Negotiation:**
- Clients and servers advertise supported protocol versions
- Negotiate highest common version
- Graceful degradation for older versions

**Backward Compatibility:**
- Protocol changes must be backward compatible where possible
- Breaking changes require major version increment
- Support for legacy versions (at least 2 versions back)

### 11.3 Data Portability

**Export:**
- Users can export all messages in standard format (mbox, maildir)
- Include decrypted content and attachments
- Preserve metadata and threading

**Import:**
- Import messages from other MailX accounts
- Import from email (IMAP, mbox, maildir)
- Preserve encryption if source supports it

## 12. Future Enhancements

### 12.1 Short-Term (Months)

- Key transparency log with gossip protocol
- Subject line encryption (move to body)
- Read receipts and typing indicators (optional)
- Group messaging with shared keys
- Mobile clients (iOS, Android)

### 12.2 Medium-Term (Year)

- Onion routing for metadata privacy
- Private Information Retrieval for key lookup
- Web client with WASM crypto
- Large file attachments (chunked upload/download)
- Voice and video calls (WebRTC)

### 12.3 Long-Term (Multi-Year)

- Mix network for traffic analysis resistance
- Post-quantum cryptography (when standards mature)
- Decentralized reputation system
- Smart contracts for paid anti-spam (optional)
- Federation with other protocols (Matrix, XMPP bridges)

## 13. Standards and References

**Cryptography:**
- NaCl/libsodium: https://nacl.cr.yp.to/
- Ed25519: RFC 8032
- X25519: RFC 7748

**Protocols:**
- gRPC: https://grpc.io/
- Protocol Buffers: https://protobuf.dev/
- TLS 1.3: RFC 8446

**Key Transparency:**
- Certificate Transparency: RFC 6962
- CONIKS: https://coniks.org/

**Related Work:**
- Signal Protocol: Double Ratchet, X3DH
- Matrix: Federation, E2EE
- PGP/GPG: Public key cryptography for email
- ActivityPub: Federated social networking
