# Roadmap - MailX Secure Email Replacement

## Vision

Build a self-hostable, federated email replacement with end-to-end encryption by default, designed to resist surveillance and centralization while remaining practical for everyday use.

## Guiding Principles

1. **Privacy First**: E2EE by default, minimal metadata
2. **Self-Hosting First**: Easy to deploy and maintain
3. **Decentralization**: No central authority or single point of failure
4. **Pragmatic Security**: Balance security with usability
5. **Open Standards**: Documented protocol, multiple implementations encouraged

## Milestones

### Demo v0.1 (Current Phase) - Target: Q1 2026

**Goal:** Minimal working system demonstrating core concepts

**Deliverables:**
- ✅ Repository structure and documentation
  - ✅ PRD for Server and Client
  - ✅ Architecture documentation
  - ✅ Threat model
  - ✅ Protocol specification
  - ✅ This roadmap
- [ ] Server implementation (Go)
  - [ ] User account management (register, login)
  - [ ] Basic federation (server discovery, mTLS)
  - [ ] Message routing (local and remote delivery)
  - [ ] Storage (SQLite with encrypted blobs)
  - [ ] E2EE placeholder (libsodium integration)
- [ ] Client implementation (Go CLI)
  - [ ] Account creation
  - [ ] Key generation and management
  - [ ] Send and receive messages
  - [ ] Basic crypto (encrypt/decrypt with libsodium)
- [ ] Demo setup
  - [ ] Docker Compose for 3 servers + 3 clients
  - [ ] Sample configuration
  - [ ] Setup and run scripts
  - [ ] Demo walkthrough documentation

**Success Criteria:**
- Alice on server A can send encrypted message to Bob on server B
- Bob can decrypt and read message
- Carol on server C can also exchange messages
- All communication uses E2EE
- Demo runs on single machine with Docker

**Timeline:**
- Week 1: Documentation (DONE)
- Week 2: Server skeleton and federation basics
- Week 3: Client skeleton and crypto integration
- Week 4: Demo setup and testing

**Status:** In Progress

---

### Alpha v0.2 - Target: Q2 2026

**Goal:** Feature-complete core protocol, ready for early adopters

**Server Features:**
- Full gRPC API implementation
- Rate limiting and quota enforcement
- First-contact protocol (request/accept workflow)
- Multi-device support (device keys)
- Message search (metadata only)
- Admin API for user management
- Prometheus metrics
- Structured logging (JSON)
- Configuration validation
- PostgreSQL support (optional)

**Client Features:**
- GUI client (desktop: Linux, macOS, Windows)
  - Using Go with Fyne or Qt bindings
- Rich text message composition
- File attachments (up to 25 MB)
- Contact management with trust levels
- Multi-folder support (Inbox, Sent, Archive, etc.)
- Offline message queue
- Local message cache
- Encrypted key storage (OS keychain)
- Message threading

**Security:**
- Comprehensive unit and integration tests
- Basic fuzz testing on message parser
- Internal security review
- Dependency vulnerability scanning (CI)
- Static analysis (gosec)

**Documentation:**
- API reference (generated from protobufs)
- Admin guide (deployment, configuration)
- User guide (client usage)
- Federation guide (connecting servers)

**Success Criteria:**
- 100+ users across 10+ servers in testing
- Zero critical security vulnerabilities
- < 1% message delivery failure rate
- End-to-end encrypted communication fully functional
- Can migrate from Demo v0.1 without data loss

**Timeline:** 3 months after Demo v0.1

**Status:** Planned

---

### Beta v0.8 - Target: Q3-Q4 2026

**Goal:** Production-ready system with advanced security features

**New Features:**

**Server:**
- Key transparency log (basic implementation)
  - Append-only log of key operations
  - Merkle tree proofs
  - Signed tree heads
- Forward secrecy (Double Ratchet protocol)
- Subject line encryption (moved to message body)
- Group messaging (basic shared keys)
- Message export/import (data portability)
- Automatic key rotation scheduling
- HSM support for domain keys (optional)
- Horizontal scaling (multiple servers per domain)

**Client:**
- Mobile apps (iOS and Android, basic)
- Web client (React + WASM crypto)
- QR code device pairing
- Improved offline support (service workers)
- Read receipts (optional, privacy-respecting)
- Typing indicators (optional)
- Message reactions
- Search index encryption

**Federation:**
- Key transparency gossip protocol
  - Cross-verify keys with multiple servers
  - Detect inconsistencies
- Reputation system (track delivery success)
- Relay support (route through trusted intermediary)

**Security & Privacy:**
- External security audit (professional firm)
- Penetration testing
- Subject encryption (reduce metadata leakage)
- Padding to obscure message sizes
- Timing obfuscation (random delays)

**Operations:**
- Kubernetes deployment manifests
- Backup and restore tools
- Monitoring dashboards (Grafana)
- Incident response playbook
- Upgrade path from Alpha

**Documentation:**
- Security audit report
- Deployment best practices
- Privacy policy template
- Terms of service template
- Federation policies guide

**Success Criteria:**
- 1,000+ users across 50+ servers
- Zero critical vulnerabilities in security audit
- < 0.1% message delivery failure rate
- Key transparency log operational
- Mobile apps in App Store and Google Play
- 99% uptime for reference server

**Timeline:** 6 months after Alpha

**Status:** Planned

---

### Release v1.0 - Target: Q1 2027

**Goal:** Stable, production-ready release for general use

**Focus:**
- Bug fixes and stability improvements
- Performance optimization
- Complete documentation
- Security hardening
- Compliance certifications (if applicable)

**Final Features:**
- All Beta features mature and tested
- Key transparency fully operational
- Multiple client implementations (CLI, GUI, Web, Mobile)
- Comprehensive API documentation
- Migration tools from email (IMAP import)

**Launch:**
- Public announcement
- Marketing website
- Community forums
- Bug bounty program
- Support channels (IRC, Matrix, forums)
- Contribution guidelines

**Success Criteria:**
- Production use by 10,000+ users
- 99.9% uptime SLA for reference server
- Zero critical vulnerabilities
- Comprehensive test coverage (>80%)
- Documentation for all features
- Active community of contributors

**Timeline:** 3 months after Beta

**Status:** Planned

---

## Post-1.0 Enhancements

### Version 1.x (Iterative Improvements)

**Privacy Enhancements:**
- Mix network integration (traffic analysis resistance)
- Private Information Retrieval for key lookups
- Tor hidden service support
- VPN/proxy support

**Feature Additions:**
- Voice and video calls (WebRTC with E2EE)
- Screen sharing
- Calendar integration (encrypted events)
- Task management
- Collaborative documents (CRDT-based)

**Usability:**
- Improved onboarding flow
- Better key verification UX
- Inline media previews (with privacy controls)
- Smart filters and rules
- AI-powered search (local only)

**Federation:**
- Bridge to other protocols (Matrix, XMPP)
- Email gateway (send/receive traditional email)
- Shared block lists (opt-in)
- Federation statistics dashboard

**Enterprise:**
- LDAP/Active Directory integration
- Advanced admin controls
- Audit logging
- Compliance reporting
- Single sign-on (SSO)

### Version 2.0 (Major Evolution)

**Post-Quantum Cryptography:**
- Migrate to PQC algorithms when standards mature
- Hybrid classical+PQC during transition
- Backward compatibility with 1.x

**Decentralized Trust:**
- Web of trust model
- Decentralized reputation
- Blockchain-based key directory (if beneficial)

**Advanced Features:**
- Zero-knowledge proofs for privacy
- Homomorphic encryption for server-side search
- Secure multi-party computation
- Decentralized storage (IPFS integration)

---

## Development Process

### Branching Strategy

- `main`: Stable, production-ready code
- `develop`: Integration branch for features
- `feature/*`: Individual feature branches
- `release/*`: Release preparation branches
- `hotfix/*`: Critical bug fixes

### Release Cycle

**Alpha/Beta:**
- Release every 4-6 weeks
- Feature freeze 1 week before release
- Testing and bug fixing during freeze

**Stable (1.0+):**
- Major releases: Every 6-12 months
- Minor releases: Every 2-3 months
- Patch releases: As needed for critical bugs

### Testing Strategy

**Unit Tests:**
- All core logic (crypto, storage, routing)
- Target: >80% coverage
- Run on every commit (CI)

**Integration Tests:**
- Full message delivery flow
- Federation scenarios
- Multi-device sync
- Run before each release

**End-to-End Tests:**
- User workflows (register, send, receive)
- Docker-based test environment
- Run before each release

**Security Tests:**
- Fuzzing (continuous)
- Static analysis (every commit)
- Dependency scanning (weekly)
- Penetration testing (quarterly)

**Performance Tests:**
- Load testing (1000+ concurrent users)
- Stress testing (resource limits)
- Before major releases

### CI/CD Pipeline

**Continuous Integration:**
- GitHub Actions (or similar)
- Build on every commit
- Run unit tests
- Static analysis (gosec, go vet)
- Dependency vulnerability scan
- Code coverage reporting

**Continuous Deployment:**
- Automatic deploy to staging (develop branch)
- Manual approval for production (main branch)
- Rollback capability
- Health checks after deployment

**Artifacts:**
- Binary releases (Linux, macOS, Windows)
- Docker images (multi-arch)
- Mobile app bundles (iOS, Android)
- Checksums and signatures

---

## Task Breakdown

### Demo v0.1 Tasks

**Documentation:** (COMPLETED)
- [x] Write PRD_Server.md
- [x] Write PRD_Client.md
- [x] Write Architecture.md
- [x] Write ThreatModel.md
- [x] Write Protocol.md
- [x] Write Roadmap.md

**Server Implementation:**
- [ ] Project setup
  - [ ] Initialize Go module
  - [ ] Set up directory structure
  - [ ] Add dependencies (gRPC, protobuf, libsodium bindings)
- [ ] Core components
  - [ ] Domain key generation and storage
  - [ ] User registration and authentication
  - [ ] Message storage (SQLite)
  - [ ] gRPC server setup
- [ ] Federation
  - [ ] Server discovery (DNS + HTTPS)
  - [ ] mTLS connection handling
  - [ ] Message delivery API
- [ ] Crypto integration
  - [ ] libsodium bindings
  - [ ] Message encryption/decryption helpers
  - [ ] Signature generation/verification

**Client Implementation:**
- [ ] Project setup
  - [ ] Initialize Go module
  - [ ] CLI framework (cobra or similar)
- [ ] Core features
  - [ ] User key generation
  - [ ] Account registration
  - [ ] Login and authentication
  - [ ] Send message (encrypt + submit)
  - [ ] Receive message (fetch + decrypt)
- [ ] User interface
  - [ ] Interactive prompts
  - [ ] Message display formatting
  - [ ] Contact management

**Demo Setup:**
- [ ] Docker Compose configuration
  - [ ] 3 server containers
  - [ ] 3 client containers
  - [ ] Network configuration
- [ ] Configuration files
  - [ ] Server configs for each domain
  - [ ] Client configs for each user
- [ ] Scripts
  - [ ] Setup script (initialize servers)
  - [ ] Demo script (example message exchange)
  - [ ] Cleanup script
- [ ] Documentation
  - [ ] README for demo
  - [ ] Step-by-step walkthrough
  - [ ] Troubleshooting guide

**Testing:**
- [ ] Unit tests for crypto functions
- [ ] Integration test for message delivery
- [ ] Manual testing of demo scenario

---

## Community & Governance

### Open Source

- **License:** MIT or Apache 2.0 (permissive)
- **Repository:** GitHub (public)
- **Issue Tracker:** GitHub Issues
- **Discussions:** GitHub Discussions
- **Chat:** Matrix or IRC

### Contributions

- **Welcome:** Code, documentation, testing, design
- **Process:** Fork, branch, pull request, review
- **Guidelines:** CONTRIBUTING.md
- **Code of Conduct:** Standard open source CoC

### Decision Making

- **Benevolent Dictator:** Initial creator(s)
- **Core Team:** Active contributors with commit access
- **RFC Process:** Major changes proposed and discussed
- **Consensus:** Aim for rough consensus, voting as fallback

### Funding

- **Donations:** Accept donations for development
- **Sponsorship:** GitHub Sponsors or Open Collective
- **Grants:** Apply for open-source/privacy grants
- **Commercial Support:** Optional paid support for enterprises

---

## Success Metrics

### Demo v0.1
- ✅ Documentation complete
- 3 servers + 3 clients running
- Message exchange working
- E2EE functional
- Demo runs on single machine

### Alpha v0.2
- 100+ users
- 10+ servers
- < 1% delivery failure
- Zero critical vulnerabilities
- Basic GUI client

### Beta v0.8
- 1,000+ users
- 50+ servers
- < 0.1% delivery failure
- Security audit passed
- Mobile apps launched

### v1.0
- 10,000+ users
- 100+ servers
- 99.9% uptime
- Active community
- Multiple implementations

### Long-term Vision
- 100,000+ users
- 1,000+ servers
- Standard protocol (RFC)
- Multiple client/server implementations
- Real alternative to email for privacy-conscious users

---

## Risks & Mitigation

### Technical Risks

**Risk:** Crypto implementation flaws
**Mitigation:** Use vetted libraries (libsodium), security audits, bug bounty

**Risk:** Performance bottlenecks
**Mitigation:** Early performance testing, optimization, horizontal scaling

**Risk:** Complex protocol hard to implement
**Mitigation:** Clear specification, reference implementation, test vectors

### Adoption Risks

**Risk:** Too complex for average users
**Mitigation:** Focus on UX, good defaults, clear documentation

**Risk:** Network effects favor established systems
**Mitigation:** Interoperability (email bridge), gradual migration path

**Risk:** Lack of killer features vs email
**Mitigation:** Emphasize privacy/security, modern UX, no spam

### Operational Risks

**Risk:** High operational burden for self-hosting
**Mitigation:** Simple deployment, minimal dependencies, good defaults

**Risk:** Security vulnerabilities in the wild
**Mitigation:** Fast patching, automatic updates, security mailing list

**Risk:** Legal/regulatory challenges
**Mitigation:** E2EE limits liability, clear ToS, legal counsel

### Ecosystem Risks

**Risk:** Competing federated protocols (Matrix, XMPP)
**Mitigation:** Focus on email replacement niche, consider bridges

**Risk:** Centralization pressure (dominant servers)
**Mitigation:** Encourage self-hosting, make it easy, resist centralization

**Risk:** Abuse and spam
**Mitigation:** First-contact protocol, rate limiting, block lists

---

## Resource Requirements

### Demo v0.1
- **Time:** 4 weeks (1 developer)
- **Skills:** Go, gRPC, crypto basics, Docker
- **Tools:** Go toolchain, Docker, text editor

### Alpha v0.2
- **Time:** 3 months (2-3 developers)
- **Skills:** Go, GUI frameworks, mobile dev (optional), security
- **Tools:** Go, GUI toolkit, test infrastructure

### Beta v0.8
- **Time:** 6 months (3-5 developers)
- **Skills:** Full-stack, mobile, security auditing, DevOps
- **Budget:** $20-50k for security audit
- **Tools:** Mobile dev tools, CI/CD, monitoring

### v1.0
- **Time:** 3 months (3-5 developers)
- **Skills:** Polish, documentation, testing
- **Budget:** $10-20k for additional audits, marketing
- **Tools:** Deployment infrastructure, support systems

---

## Conclusion

This roadmap outlines an ambitious but achievable path to building a secure, federated email replacement. The phased approach allows for iterative development, early testing, and community feedback.

**Key Milestones:**
1. **Demo v0.1** - Prove the concept works
2. **Alpha v0.2** - Build a usable system
3. **Beta v0.8** - Achieve production quality
4. **v1.0** - Launch to the world

**Success Factors:**
- Strong cryptographic foundation
- Practical self-hosting experience
- Active community involvement
- Incremental feature delivery
- Continuous security focus

**Next Steps:**
- Complete Demo v0.1 implementation
- Gather early feedback
- Recruit contributors
- Build momentum toward Alpha

The future of private communication is federated, encrypted, and in users' hands. Let's build it together.

---

**Last Updated:** 2026-02-17  
**Version:** 1.0  
**Status:** Living document (updated with each milestone)
