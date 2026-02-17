# MailX Demo - Secure Federated Email Replacement

This demo demonstrates the MailX system with 3 federated servers and clients that can exchange encrypted messages.

## Architecture

The demo consists of:
- **3 Servers**: alice.local, bob.local, carol.local
- **Clients**: CLI clients for each user
- **Network**: Isolated Docker network for communication

## Prerequisites

- Docker and Docker Compose
- ~500MB disk space
- Ports 8080, 8180, 8280, 8443, 8543, 8643 available

## Quick Start

### 1. Setup

Run the setup script to build and start the servers:

```bash
./setup.sh
```

This will:
- Build Docker images for server and client
- Start 3 server instances
- Create necessary directories and configurations

### 2. Run the Demo

There are two ways to use the demo:

#### Option A: Interactive Client (Recommended)

Use the included Docker client:

```bash
docker-compose run --rm client /mailx-client /data/alice_config.json
```

Or use the pre-built client directly (if you have the binary):

```bash
cd ../client
./bin/mailx-client alice_config.json
```

#### Option B: Manual Demo Script

A pre-scripted demo showing message exchange:

```bash
./run_demo.sh
```

## Demo Walkthrough

### Step 1: Register Users

On Server A (alice.local):
```
> register alice alice.local password123 server-a.local:8443
```

On Server B (bob.local):
```
> register bob bob.local password456 server-b.local:8443
```

On Server C (carol.local):
```
> register carol carol.local password789 server-c.local:8443
```

### Step 2: Login

```
> login password123
```

### Step 3: Send a Message

Alice sends to Bob:
```
> send bob@bob.local Hello Testing the MailX system!
```

### Step 4: Check Inbox

As Bob:
```
> list inbox
```

### Step 5: Read Message

```
> read <message-id>
```

## Client Commands

```
help                                   - Show available commands
register <user> <domain> <pass> <srv>  - Register new account
login <password>                       - Login to account
send <recipient> <subject> <body>      - Send encrypted message
list [folder] [limit]                  - List messages (default: inbox, 10)
read <message-id>                      - Read and decrypt a message
exit                                   - Quit client
```

## Folders

- **inbox**: Messages from accepted contacts
- **requests**: First messages from unknown senders (requires accept)
- **sent**: Messages you sent

## Server APIs

Each server exposes:

### gRPC API (Port 8443, 8543, 8643)
- Client API: Registration, login, send/receive messages
- Federation API: Server-to-server message delivery

### HTTP API (Port 8080, 8180, 8280)
- `/.well-known/mailx-server`: Server discovery endpoint

Example:
```bash
curl http://localhost:8080/.well-known/mailx-server | jq
```

## Architecture Highlights

### End-to-End Encryption

All messages are encrypted client-side using NaCl (libsodium):
1. Client generates Ed25519 key pair on registration
2. Server signs user's public key (attestation)
3. Messages encrypted with recipient's public key
4. Server stores only encrypted blobs

### Federation

Servers discover each other via:
1. DNS TXT records (in production)
2. HTTPS well-known endpoint
3. Static configuration (demo mode)

### Security Features

- **Identity**: Ed25519 keys for users and servers
- **Authentication**: Password-based with server attestation
- **Authorization**: Token-based (JWT-style)
- **Encryption**: NaCl box for E2EE
- **Signatures**: All messages signed by sender
- **First Contact**: Unknown senders go to "requests" folder

## Testing Scenarios

### Scenario 1: Local Message Exchange

Alice and Bob on the same server:
```
alice> send alice2@alice.local Test Local message
```

### Scenario 2: Federated Message Exchange

Alice to Bob across servers:
```
alice> send bob@bob.local Test Federated message across servers!
```

### Scenario 3: Multiple Recipients

Alice to Bob and Carol:
```
alice> send bob@bob.local,carol@carol.local Test Group message
```

### Scenario 4: First Contact Workflow

Send message to new contact:
- Message goes to recipient's "requests" folder
- Recipient must accept to move to inbox
- Future messages go directly to inbox

## Troubleshooting

### Servers not starting

Check logs:
```bash
docker-compose logs server-a
docker-compose logs server-b
docker-compose logs server-c
```

### Connection refused

Ensure servers are running:
```bash
docker-compose ps
```

Check server is listening:
```bash
curl http://localhost:8080/.well-known/mailx-server
```

### Message delivery failed

Check both sender and recipient logs:
```bash
docker-compose logs server-a | grep ERROR
docker-compose logs server-b | grep ERROR
```

### Permission errors

Ensure data directories are writable:
```bash
chmod -R 777 data/
```

## Data Persistence

Server data is stored in:
- `data/server-a/` - Alice's server data
- `data/server-b/` - Bob's server data
- `data/server-c/` - Carol's server data
- `data/client/` - Client configurations

To reset:
```bash
rm -rf data/server-* data/client
./setup.sh
```

## Configuration

Server configurations in `config/`:
- `server-a.json` - Alice's server (alice.local)
- `server-b.json` - Bob's server (bob.local)
- `server-c.json` - Carol's server (carol.local)

Default settings:
- Max message size: 25 MB
- Default quota: 10 GB per user
- No TLS (demo only - production should use TLS)

## Network Architecture

```
┌─────────────────────────────────────────────────┐
│              Docker Network                     │
│                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  │   Server A   │  │   Server B   │  │   Server C   │
│  │ alice.local  │  │  bob.local   │  │ carol.local  │
│  │   :8443      │  │   :8443      │  │   :8443      │
│  └──────────────┘  └──────────────┘  └──────────────┘
│         ▲                 ▲                 ▲         │
│         │                 │                 │         │
│         └─────────────────┴─────────────────┘         │
│                      │                                │
│                      │                                │
│               ┌──────▼────────┐                       │
│               │    Client     │                       │
│               └───────────────┘                       │
│                                                 │
└─────────────────────────────────────────────────┘
         │              │              │
         │              │              │
    localhost:8443  localhost:8543  localhost:8643
```

## Security Notes

⚠️ **This is a DEMO configuration**:
- No TLS (messages encrypted but metadata visible)
- Simplified password hashing
- No rate limiting enforced
- Containers run as root
- Insecure token generation

**DO NOT use in production without**:
- Proper TLS certificates
- bcrypt/argon2 password hashing
- Rate limiting and DoS protection
- Proper JWT implementation
- Security hardening
- External security audit

## Next Steps

After running the demo:

1. **Explore the code**: See how E2EE is implemented
2. **Read the docs**: Check `/docs` for architecture and PRDs
3. **Extend the demo**: Add more users, test edge cases
4. **Contribute**: Report issues, suggest improvements

## Cleanup

To stop and remove everything:

```bash
docker-compose down -v
rm -rf data/
```

## Support

- **Issues**: https://github.com/albahrani/mailx/issues
- **Docs**: See `/docs` directory
- **Security**: See `docs/ThreatModel.md`

## License

See LICENSE file in repository root.
