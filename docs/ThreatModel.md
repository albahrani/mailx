# Threat Model - MailX Secure Email Replacement

## 1. Introduction

This document analyzes the security threats facing the MailX system and describes how the architecture mitigates these threats. We adopt a structured threat modeling approach covering assets, adversaries, attack surfaces, and mitigations.

## 2. Assets and Trust Boundaries

### 2.1 Assets to Protect

**High-Value Assets:**
1. **Message Content**: The actual text and attachments in messages
   - Confidentiality: Must remain secret from all except sender and intended recipients
   - Integrity: Must not be modified without detection
   
2. **User Private Keys**: Cryptographic keys for decryption and signing
   - Loss = account compromise
   - Must never leave user's control
   
3. **Server Domain Keys**: Root keys for domain identity
   - Loss = domain impersonation
   - Server operator's responsibility

**Medium-Value Assets:**
4. **Message Metadata**: Sender, recipient, timestamp, size
   - Some exposure acceptable, but minimize
   - Can reveal communication patterns
   
5. **Contact Lists**: Who communicates with whom
   - Privacy concern, not critical security
   
6. **User Credentials**: Passwords, authentication tokens
   - Access to account and messages

**Low-Value Assets:**
7. **Server Configuration**: Rate limits, quotas, policies
   - Mostly public information
   - Some settings may reveal defensive posture

### 2.2 Trust Boundaries

```
┌─────────────────────────────────────────────────┐
│              Trusted Zone                       │
│  ┌──────────────────────────────────┐          │
│  │     User's Device                │          │
│  │  - Private keys                  │          │
│  │  - Decrypted messages            │          │
│  │  - Client application            │          │
│  └──────────────────────────────────┘          │
└─────────────────────────────────────────────────┘
                     │
                     │ TLS
                     ▼
┌─────────────────────────────────────────────────┐
│           Semi-Trusted Zone                     │
│  ┌──────────────────────────────────┐          │
│  │     User's Server                │          │
│  │  - Encrypted messages            │          │
│  │  - Message metadata              │          │
│  │  - Server private key            │          │
│  └──────────────────────────────────┘          │
└─────────────────────────────────────────────────┘
                     │
                     │ mTLS
                     ▼
┌─────────────────────────────────────────────────┐
│            Untrusted Zone                       │
│  ┌──────────────────────────────────┐          │
│  │     Remote Server                │          │
│  │  - Encrypted blobs only          │          │
│  │  - Observable metadata           │          │
│  └──────────────────────────────────┘          │
└─────────────────────────────────────────────────┘
```

**Trust Levels:**
- **User's Device**: Fully trusted, highest security requirements
- **User's Server**: Semi-trusted, honest-but-curious model
- **Remote Servers**: Untrusted, potentially malicious
- **Network**: Untrusted, assume adversarial

## 3. Adversary Model

### 3.1 Adversary Types

#### 3.1.1 Passive Network Observer
**Capabilities:**
- Monitor network traffic
- Collect metadata (IP addresses, timestamps, packet sizes)
- Perform traffic analysis and timing correlation

**Limitations:**
- Cannot decrypt TLS traffic
- Cannot modify packets (only observe)

**Mitigations:**
- TLS 1.3 for all connections
- mTLS for server federation
- Future: Timing obfuscation, cover traffic

#### 3.1.2 Active Network Attacker
**Capabilities:**
- All passive capabilities
- Drop, delay, or reorder packets
- Attempt protocol-level attacks
- Perform denial of service

**Limitations:**
- Cannot forge TLS certificates (without CA compromise)
- Cannot decrypt traffic
- Cannot forge message signatures

**Mitigations:**
- Certificate pinning for server keys
- Message signatures prevent forgery
- Retry logic for dropped messages
- Rate limiting for DoS

#### 3.1.3 Malicious Server Operator
**Capabilities:**
- Access all data stored on server
- Read message metadata
- Attempt key substitution attacks
- Delay or drop messages selectively
- Monitor user activity on server

**Limitations:**
- Cannot decrypt E2EE message content
- Cannot forge user signatures (without user key)
- Key substitution detectable via key transparency

**Mitigations:**
- End-to-end encryption (server cannot read content)
- Key transparency log (detects key substitution)
- Client-side signature verification
- Users can choose different server if distrusted

#### 3.1.4 Compromised Server
**Capabilities:**
- All malicious operator capabilities
- Access to server private keys
- Modify server software
- Install backdoors

**Limitations:**
- Cannot decrypt historical messages (if keys rotated)
- Cannot decrypt messages to other domains
- Key compromise detectable if key transparency is monitored

**Mitigations:**
- Forward secrecy (future, via Double Ratchet)
- Key rotation with short lifetimes
- Encryption at rest for defense in depth
- Intrusion detection systems

#### 3.1.5 Malicious Client/User
**Capabilities:**
- Spam other users
- Attempt to enumerate users
- Share received messages (not a technical problem)
- Abuse server resources

**Limitations:**
- Cannot impersonate other users (signature required)
- Cannot bypass rate limits (enforced server-side)
- Cannot read others' messages

**Mitigations:**
- First-contact protocol (spam filtering)
- Rate limiting per user
- Resource quotas
- Block lists and abuse reporting

#### 3.1.6 State-Level Adversary
**Capabilities:**
- Compel server operators to cooperate
- Large-scale surveillance infrastructure
- Advanced traffic analysis
- Potentially compromise CA infrastructure
- Social engineering and targeted attacks

**Limitations:**
- Cannot break strong cryptography (assumption)
- Cannot compromise all servers simultaneously
- Users can migrate to servers outside jurisdiction

**Mitigations:**
- E2EE limits what can be compelled
- Federation allows jurisdiction shopping
- Key transparency catches some attacks
- Out-of-band key verification for high-risk users
- Future: Tor support, mix networks

**Note:** Full protection against state-level adversaries is out of scope. We aim to raise the cost and detectability of attacks.

## 4. Attack Surfaces

### 4.1 Client Attack Surface

**Entry Points:**
1. Network input from server
2. User input (message composition, settings)
3. File system (message cache, keys)
4. Operating system integration

**Potential Vulnerabilities:**
- Buffer overflows in message parsing
- Code injection via crafted messages
- Private key theft from disk
- UI spoofing attacks
- Dependency vulnerabilities

**Mitigations:**
- Memory-safe languages (Go, Rust)
- Input validation and sanitization
- Encrypted key storage with OS keychain
- Regular dependency updates
- Code reviews and security audits

### 4.2 Server Attack Surface

**Entry Points:**
1. Client API (authenticated gRPC)
2. Federation API (mTLS gRPC)
3. Admin API (authenticated gRPC)
4. Database

**Potential Vulnerabilities:**
- Authentication bypass
- SQL injection (if not using prepared statements)
- DoS via resource exhaustion
- Privilege escalation
- Configuration errors

**Mitigations:**
- Strong authentication (bcrypt, rate limiting)
- Parameterized queries (ORM)
- Rate limiting and quotas
- Principle of least privilege
- Configuration validation
- Regular security updates

### 4.3 Federation Attack Surface

**Entry Points:**
1. mTLS connections from peers
2. DNS/HTTPS discovery endpoints

**Potential Vulnerabilities:**
- Rogue servers impersonating domains
- Man-in-the-middle attacks
- DNS poisoning
- Certificate substitution

**Mitigations:**
- Verify domain keys against DNS+HTTPS
- Certificate pinning
- DNSSEC (where available)
- Key transparency (future)

### 4.4 Cryptographic Attack Surface

**Entry Points:**
1. Key generation
2. Encryption/decryption operations
3. Signature generation/verification
4. Random number generation

**Potential Vulnerabilities:**
- Weak random number generator
- Side-channel attacks (timing, power)
- Implementation flaws in crypto library
- Downgrade attacks

**Mitigations:**
- Use system CSPRNG
- Constant-time crypto operations (libsodium)
- Vetted crypto libraries (libsodium)
- Protocol version negotiation with minimum versions
- No custom crypto implementations

## 5. Threat Scenarios and Mitigations

### 5.1 Confidentiality Threats

#### T1: Eavesdropping on Message Content
**Threat:** Network attacker intercepts messages
**Impact:** Critical - message content exposed
**Mitigations:**
- ✅ End-to-end encryption (even server cannot read)
- ✅ TLS for all network communication
- ✅ No plaintext option
**Residual Risk:** Low - requires breaking E2EE

#### T2: Server Operator Reading Messages
**Threat:** Server admin accesses database
**Impact:** Critical if no E2EE
**Mitigations:**
- ✅ End-to-end encryption
- ✅ Encryption at rest (defense in depth)
- ✅ Server only stores encrypted blobs
**Residual Risk:** Low - server cannot decrypt

#### T3: Metadata Leakage
**Threat:** Observers learn who communicates with whom
**Impact:** Medium - privacy concern
**Mitigations:**
- ✅ TLS hides content from network
- ⚠️ Server sees sender/recipient (necessary for routing)
- 🔮 Future: Onion routing, mix networks
**Residual Risk:** Medium - metadata still visible to servers

#### T4: Key Theft from Client Device
**Threat:** Malware steals private keys
**Impact:** Critical - account compromise
**Mitigations:**
- ✅ Encrypted key storage
- ✅ OS keychain integration
- ⚠️ Requires trusted device
**Residual Risk:** Medium - dependent on OS security

### 5.2 Integrity Threats

#### T5: Message Modification in Transit
**Threat:** Attacker modifies message during delivery
**Impact:** High - message integrity compromised
**Mitigations:**
- ✅ Authenticated encryption (Poly1305)
- ✅ Digital signatures (Ed25519)
- ✅ TLS prevents network tampering
**Residual Risk:** Low - cryptographically protected

#### T6: Message Injection/Forgery
**Threat:** Attacker sends message impersonating Alice
**Impact:** High - impersonation attack
**Mitigations:**
- ✅ All messages signed by sender's private key
- ✅ Server verifies sender identity
- ✅ Recipient verifies signature
**Residual Risk:** Low - requires compromising private key

#### T7: Replay Attacks
**Threat:** Attacker re-sends old message
**Impact:** Medium - duplicate message delivery
**Mitigations:**
- ✅ Unique message IDs
- ✅ Timestamp checking
- ✅ Nonce-based deduplication
**Residual Risk:** Low - detected and rejected

### 5.3 Availability Threats

#### T8: Denial of Service (DoS)
**Threat:** Attacker floods server with requests
**Impact:** High - service unavailable
**Mitigations:**
- ✅ Rate limiting per IP, per domain, per user
- ✅ Connection limits
- ✅ Request timeouts
- ✅ Resource quotas
**Residual Risk:** Medium - cannot fully prevent DDoS

#### T9: Storage Exhaustion
**Threat:** Attacker fills disk with spam messages
**Impact:** Medium - service degraded
**Mitigations:**
- ✅ Per-user storage quotas
- ✅ Message size limits
- ✅ First-contact protocol (spam filter)
**Residual Risk:** Low - quotas prevent exhaustion

#### T10: Message Delivery Failure
**Threat:** Messages lost due to server/network failure
**Impact:** Medium - messages not delivered
**Mitigations:**
- ✅ Retry logic with exponential backoff
- ✅ Dead letter queue for failed messages
- ⚠️ No guarantee of delivery (best effort)
**Residual Risk:** Medium - accept as inherent to distributed system

### 5.4 Authentication Threats

#### T11: Password Guessing/Brute Force
**Threat:** Attacker guesses user password
**Impact:** High - account takeover
**Mitigations:**
- ✅ bcrypt with high cost factor
- ✅ Rate limiting on login attempts
- ✅ Account lockout after failures
- ✅ Optional 2FA (TOTP)
**Residual Risk:** Low - strong password required

#### T12: Session Hijacking
**Threat:** Attacker steals session token
**Impact:** High - temporary account access
**Mitigations:**
- ✅ Short-lived JWT tokens
- ✅ Secure token storage
- ✅ TLS prevents network interception
- ✅ Token refresh mechanism
**Residual Risk:** Low - requires compromising client device

#### T13: Server Impersonation
**Threat:** Rogue server pretends to be legitimate domain
**Impact:** Critical - MITM attack
**Mitigations:**
- ✅ Domain keys published via DNS+HTTPS
- ✅ mTLS with certificate verification
- ✅ Certificate pinning
- 🔮 Future: Key transparency log
**Residual Risk:** Medium - DNS compromise possible

### 5.5 Privacy Threats

#### T14: User Enumeration
**Threat:** Attacker discovers all users on a server
**Impact:** Low - privacy leak
**Mitigations:**
- ✅ Key lookups require authentication
- ✅ Constant-time responses
- ⚠️ Existence revealed during message delivery
**Residual Risk:** Medium - full protection difficult

#### T15: Traffic Analysis
**Threat:** Attacker correlates encrypted traffic
**Impact:** Medium - reveals communication patterns
**Mitigations:**
- ✅ TLS hides content
- ⚠️ Timing and size still observable
- 🔮 Future: Cover traffic, constant-rate transmission
**Residual Risk:** High - hard to fully mitigate

#### T16: Contact Discovery
**Threat:** Third party learns user's contact list
**Impact:** Low - social graph exposure
**Mitigations:**
- ⚠️ Contact list stored on server (encrypted)
- ✅ Not publicly accessible
- ✅ Requires authentication
**Residual Risk:** Low - server operator can see

### 5.6 Advanced Threats

#### T17: Key Substitution Attack
**Threat:** Server substitutes user's public key
**Impact:** Critical - MITM at E2EE layer
**Mitigations:**
- ✅ Server signs user keys (attestation)
- 🔮 Key transparency log (future) detects changes
- ✅ Out-of-band key verification for sensitive contacts
**Residual Risk:** Medium - mitigated but not eliminated until key transparency deployed

#### T18: Sybil Attack
**Threat:** Attacker creates many fake identities
**Impact:** Medium - spam, vote manipulation (if voting added)
**Mitigations:**
- ✅ First-contact protocol
- ⚠️ No proof-of-work or identity verification
- ✅ Per-domain rate limits
**Residual Risk:** Medium - inherent to open systems

#### T19: Long-Term Archive Compromise
**Threat:** Future quantum computer breaks encryption
**Impact:** High - historical messages decrypted
**Mitigations:**
- ⚠️ Current crypto not post-quantum safe
- 🔮 Future: Post-quantum algorithms when mature
- ✅ Forward secrecy (future) limits exposure
**Residual Risk:** High - long-term concern

#### T20: Supply Chain Attack
**Threat:** Compromised dependency or build process
**Impact:** Critical - backdoor in software
**Mitigations:**
- ✅ Dependency pinning and verification
- ✅ Reproducible builds
- ✅ Code review and audits
- ✅ Open source (community review)
**Residual Risk:** Medium - cannot eliminate entirely

## 6. Security Assumptions

### 6.1 Cryptographic Assumptions

**We Assume:**
1. Ed25519 provides 128-bit security (quantum: ~64-bit)
2. XSalsa20-Poly1305 is secure for authenticated encryption
3. BLAKE2b provides collision resistance
4. Discrete logarithm problem is hard (until quantum computers)
5. Random number generators are cryptographically secure

**If Assumptions Break:**
- Algorithm compromise: Protocol supports version negotiation, can migrate to new algorithms
- Implementation flaw: Use vetted libraries (libsodium), apply patches quickly
- Quantum computers: Transition to post-quantum crypto (future work)

### 6.2 Infrastructure Assumptions

**We Assume:**
1. DNS is not globally compromised
   - Use DNSSEC where available
   - Cross-check via HTTPS
2. Certificate Authorities are not systematically malicious
   - Use domain keys as primary trust anchor
   - CAs are optional/secondary
3. Operating systems are not backdoored
   - Use open-source OS where possible
   - User responsibility to vet their platform

**If Assumptions Break:**
- DNS compromise: Certificate pinning, key transparency, manual verification
- CA compromise: Domain keys provide independent trust path
- OS compromise: No technical mitigation (out of scope)

### 6.3 Implementation Assumptions

**We Assume:**
1. No critical bugs in our code
   - Mitigate via code review, testing, audits
2. No critical bugs in dependencies
   - Monitor security advisories, update promptly
3. Developers follow secure coding practices
   - Training, guidelines, automated checks

**If Assumptions Break:**
- Security vulnerability disclosed: Issue patch, notify users
- Zero-day exploited: Incident response plan, forensics
- Persistent issues: Consider rewrite in memory-safe language

### 6.4 Operational Assumptions

**We Assume:**
1. Server operators competently configure systems
   - Provide good defaults, configuration validation
   - Documentation and setup guides
2. Users protect their devices and passwords
   - User education, security prompts
   - Cannot force users to be secure
3. Some server operators will be malicious
   - Design assuming honest-but-curious servers
   - Key transparency to detect misbehavior

**If Assumptions Break:**
- Incompetent operator: System degrades gracefully, other servers unaffected
- User device compromise: Account takeover possible, limit blast radius
- Malicious operator: E2EE and key transparency limit damage

## 7. Security Requirements Summary

### 7.1 MUST Have (Critical)

- ✅ End-to-end encryption for all messages
- ✅ Digital signatures on all messages
- ✅ Authenticated encryption (no plaintext mode)
- ✅ TLS 1.3 for all network communication
- ✅ mTLS for server federation
- ✅ Secure key storage on client
- ✅ Strong password hashing (bcrypt)
- ✅ Rate limiting and DoS protection
- ✅ Input validation and sanitization

### 7.2 SHOULD Have (Important)

- ✅ Key rotation support
- ✅ Multi-device synchronization
- ✅ Encryption at rest on server
- ✅ Security event logging
- ⏳ Key transparency log (future)
- ⏳ Forward secrecy (future)
- ⏳ Subject line encryption (future)

### 7.3 COULD Have (Nice-to-Have)

- ⏳ Post-quantum cryptography
- ⏳ Onion routing for metadata privacy
- ⏳ Private Information Retrieval
- ⏳ Mix network integration
- ⏳ Tor hidden service support

## 8. Security Testing

### 8.1 Threat-Driven Testing

**Test Each Threat:**
- T1-T20: Create test cases for each scenario
- Verify mitigations are effective
- Document residual risks

### 8.2 Penetration Testing

**Scope:**
- Network attacks (MITM, DoS)
- Authentication bypass attempts
- Authorization vulnerabilities
- Crypto implementation flaws
- Federation protocol attacks

**Frequency:**
- Before major releases
- After significant security changes
- At least annually

### 8.3 Fuzzing

**Targets:**
- Message parsing
- Protocol buffer handling
- gRPC endpoints
- Crypto operations

**Tools:**
- AFL, libFuzzer for C/C++ code
- go-fuzz for Go code

### 8.4 Static Analysis

**Tools:**
- gosec for Go security issues
- Dependency vulnerability scanning
- License compliance checking

**CI Integration:**
- Run on every commit
- Block merge on critical findings

### 8.5 Security Audits

**External Audits:**
- Hire professional security firm
- Focus on crypto, authentication, federation
- Before 1.0 release

**Bug Bounty:**
- Public bug bounty program after beta
- Responsible disclosure policy
- Reward for finding vulnerabilities

## 9. Incident Response

### 9.1 Vulnerability Disclosure

**Process:**
1. Security contact: security@mailx.dev (example)
2. Encrypted communication (PGP key published)
3. Acknowledge receipt within 48 hours
4. Investigate and develop fix
5. Coordinate disclosure timeline (90 days default)
6. Release patch and advisory

### 9.2 Security Advisories

**Format:**
- CVE number (if applicable)
- Severity rating (CVSS score)
- Affected versions
- Mitigation steps
- Patch availability

**Distribution:**
- GitHub Security Advisories
- Mailing list for server operators
- Public announcement after patch release

### 9.3 Compromise Recovery

**Server Key Compromise:**
1. Generate new domain key pair
2. Publish new key via DNS and HTTPS
3. Notify all federated peers
4. Revoke old key
5. Monitor for misuse of old key

**User Key Compromise:**
1. User generates new key pair
2. Register with server
3. Notify contacts
4. Revoke old key
5. Re-encrypt critical messages

## 10. Security Roadmap

### 10.1 Phase 1: Demo v0.1 (Current)
- ✅ Basic E2EE with libsodium
- ✅ TLS for client-server
- ✅ mTLS for federation
- ✅ Password authentication
- ✅ Rate limiting

### 10.2 Phase 2: Alpha
- Key transparency log (basic)
- Forward secrecy (Double Ratchet)
- Subject encryption
- Security audit (internal)
- Penetration testing

### 10.3 Phase 3: Beta
- Key transparency gossip protocol
- Advanced traffic analysis resistance
- External security audit
- Bug bounty program
- Formal security documentation

### 10.4 Phase 4: Production 1.0
- All critical mitigations implemented
- Security certifications (if applicable)
- Incident response team
- 24/7 security monitoring
- Regular security updates

### 10.5 Phase 5: Future
- Post-quantum cryptography
- Hardware security module (HSM) support
- Formal verification of critical components
- Zero-knowledge proofs for privacy
- Decentralized trust models

## 11. Conclusion

The MailX threat model identifies significant security challenges in building a secure email replacement. Our architecture provides strong protection against most threats through:

1. **End-to-end encryption** prevents content access by servers and network attackers
2. **Digital signatures** prevent message forgery and impersonation
3. **mTLS federation** secures server-to-server communication
4. **Key transparency** (future) detects key substitution attacks
5. **Rate limiting and quotas** mitigate abuse and DoS

**Key Residual Risks:**
- Metadata visibility to servers (partial mitigation via future work)
- Traffic analysis (difficult problem, future work)
- Endpoint security (user responsibility)
- State-level adversaries (out of scope for most users)

**Security Posture:**
MailX provides significantly better security than traditional email while acknowledging that perfect security is impossible. We prioritize practical, deployable security over theoretical ideals, with a roadmap for continuous improvement.

**Legend:**
- ✅ Implemented
- ⚠️ Partial mitigation
- 🔮 Future work
- ⏳ Planned but not yet implemented
