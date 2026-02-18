# MailX - Secure Federated Email Replacement

A modern, secure, self-hostable alternative to email with end-to-end encryption by default.

## Overview

MailX is a federated messaging system designed to replace traditional email with better security and privacy. It features:

- **End-to-end encryption by default** - All messages encrypted with NaCl box (X25519 + XSalsa20-Poly1305)
- **Federated architecture** - No central authority, run your own server
- **Domain-based identity** - Simple username@domain addressing
- **First-contact security** - Unknown senders require acceptance
- **Open protocol** - Documented gRPC/protobuf specification
- **Self-hosting first** - Minimal dependencies, easy to deploy

## Quick Start

### Run the Demo

```bash
cd demo
./setup.sh
```

Windows (PowerShell):

```powershell
cd demo
./setup.ps1
```

This starts 3 servers (alice.local, bob.local, carol.local) that can exchange encrypted messages.

See [demo/README.md](demo/README.md) for detailed walkthrough.

## Repository Structure

```
mailx/
├── docs/              # Comprehensive documentation
│   ├── PRD_Server.md      # Server product requirements
│   ├── PRD_Client.md      # Client product requirements
│   ├── Architecture.md    # System architecture
│   ├── ThreatModel.md     # Security threat model
│   ├── Protocol.md        # Protocol specification
│   └── Roadmap.md         # Development roadmap
  ├── server/            # Go server implementation
│   ├── cmd/server/        # Server entry point
│   ├── internal/          # Internal packages
│   │   ├── crypto/        # Cryptography (NaCl box, Ed25519)
│   │   ├── storage/       # Database (SQLite)
│   │   └── federation/    # Server discovery
│   └── proto/             # gRPC protocol definitions
├── client/            # Go CLI client implementation
│   ├── cmd/client/        # Client entry point
│   └── internal/crypto/   # Client-side crypto
└── demo/              # Docker-based demo setup
    ├── docker-compose.yml # 3 servers + client (Docker Compose)
    ├── config/            # Server configurations
    └── README.md          # Demo walkthrough
```

## Documentation

Comprehensive documentation in `/docs`:

- **[PRD_Server.md](docs/PRD_Server.md)** - Server requirements: federation, identity, anti-abuse, storage, etc.
- **[PRD_Client.md](docs/PRD_Client.md)** - Client requirements: key management, UX, multi-device, etc.
- **[Architecture.md](docs/Architecture.md)** - System design: identity model, E2EE, federation protocol
- **[ThreatModel.md](docs/ThreatModel.md)** - Security analysis: threats, mitigations, assumptions
- **[Protocol.md](docs/Protocol.md)** - Wire protocol specification (gRPC/protobuf)
- **[Roadmap.md](docs/Roadmap.md)** - Development plan: Demo → Alpha → Beta → v1.0

## Features

### Current (Demo v0.1)

- ✅ **Server**: Go-based gRPC server with SQLite storage
- ✅ **Client**: Go CLI client with interactive mode
- ✅ **E2EE**: NaCl box encryption for all messages
- ✅ **Federation**: Server discovery via well-known endpoints
- ✅ **Identity**: Server-attested user encryption keys (NaCl box/X25519) with Ed25519 signing attestations (`signKey`)
- ✅ **Demo**: Docker Compose setup with 3 servers

### Planned (See Roadmap)

- **Alpha**: GUI client, key transparency, multi-device support
- **Beta**: Mobile apps, forward secrecy, external security audit
- **v1.0**: Production-ready with full security features

## Security

### Cryptography

- **Signatures**: Ed25519 (used by servers to sign key attestations)
- **Encryption**: NaCl box (X25519 + XSalsa20-Poly1305) for message E2EE
- **Library**: Go `x/crypto/nacl/box` + `x/crypto/ed25519`

### Trust Model

- **Domain keys** as root of trust (published via DNS/HTTPS)
- **Server attestation** of user public keys
- **Trust on first use** (TOFU) for contacts
- **Key transparency** (future) for detecting key substitution

### Threat Protection

See [docs/ThreatModel.md](docs/ThreatModel.md) for complete analysis.

- ✅ Content confidentiality (E2EE)
- ✅ Key integrity for contact keys (server-signed key attestations)
- ⚠️ Metadata privacy (partial - TLS only)
- 🔮 Traffic analysis resistance (future)

## Building from Source

### Server

```bash
cd server
go build -o bin/mailx-server cmd/server/main.go
./bin/mailx-server config.json
```

### Client

```bash
cd client
go build -o bin/mailx-client cmd/client/main.go
./bin/mailx-client
```

Windows (PowerShell):

```powershell
cd server
go build -o bin\mailx-server.exe cmd\server\main.go
./bin/mailx-server.exe config.json

cd ..\client
go build -o bin\mailx-client.exe cmd\client\main.go
./bin/mailx-client.exe
```

### Requirements

- Go 1.24+
- Protocol Buffers compiler (protoc)
- SQLite

## Contributing

This is an early-stage project. Contributions welcome!

**Areas needing help:**
- Security review and testing
- Client implementations (GUI, mobile)
- Documentation improvements
- Federation testing
- Performance optimization

See [docs/Roadmap.md](docs/Roadmap.md) for planned features.

## License

[License TBD - Recommend MIT or Apache 2.0 for open source]

## Goals

From the project vision:

1. **Privacy First** - E2EE by default, minimal metadata
2. **Self-Hosting First** - Easy to deploy and maintain
3. **Decentralization** - No central authority required
4. **Pragmatic Security** - Balance security with usability
5. **Open Standards** - Documented protocol, interoperable

## Status

**Current Phase**: Demo v0.1 ✅

- Functional server and client
- E2EE message exchange working
- 3-server federation demo operational
- Comprehensive documentation complete

**Next Phase**: Alpha v0.2 (Q2 2026)

- GUI client
- Key transparency
- External security review
- 100+ users across 10+ servers

See [docs/Roadmap.md](docs/Roadmap.md) for full timeline.

## Contact

- **Repository**: https://github.com/albahrani/mailx
- **Issues**: https://github.com/albahrani/mailx/issues
- **Security**: See [docs/ThreatModel.md](docs/ThreatModel.md)

---

**⚠️ Security Notice**: This is demo software. Do not use for sensitive communications without a security audit. See threat model for limitations.
