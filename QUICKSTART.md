# MailX Quick Start Guide

Get MailX running in under 5 minutes!

## Option 1: Docker Demo (Recommended)

The easiest way to try MailX:

```bash
cd demo
./setup.sh
```

This starts 3 federated servers. Then run:

```bash
docker-compose run --rm client /mailx-client /data/alice.json
```

See [demo/README.md](demo/README.md) for complete demo walkthrough.

## Option 2: Local Build

Build and run from source:

### Prerequisites

- Go 1.21+
- Protocol Buffers compiler
- SQLite

### Build

```bash
# Build server
cd server
go build -o bin/mailx-server cmd/server/main.go

# Build client  
cd ../client
go build -o bin/mailx-client cmd/client/main.go
```

### Run Server

Create config.json:

```json
{
  "domain": "myserver.local",
  "grpcPort": "8443",
  "httpPort": "8080",
  "databasePath": "./mailx.db",
  "serverKeyFile": "./server_key.json",
  "maxMessageSize": 26214400,
  "defaultQuota": 10737418240
}
```

Start server:

```bash
./bin/mailx-server config.json
```

### Run Client

```bash
./bin/mailx-client
```

In the client:

```
> register alice myserver.local password123 localhost:8443
> login password123
> send alice@myserver.local test Hello World!
> list inbox
> read <message-id>
```

## Basic Usage

### Register Account

```
> register <username> <domain> <password> <server-address>
```

Example:
```
> register alice alice.local password123 localhost:8443
```

### Login

```
> login <password>
```

### Send Message

```
> send <recipient@domain> <subject> <message body>
```

Example:
```
> send bob@bob.local Hello How are you?
```

### List Messages

```
> list [folder] [limit]
```

Examples:
```
> list inbox
> list sent
> list requests 20
```

### Read Message

```
> read <message-id>
```

Get message-id from the list command.

## Architecture Overview

```
┌─────────────┐                    ┌─────────────┐
│   Client A  │◄──── gRPC/TLS ────►│  Server A   │
│  (alice)    │                    │ alice.local │
└─────────────┘                    └──────┬──────┘
                                          │
                                    mTLS  │
                                          │
                                    ┌─────▼──────┐
                                    │  Server B  │
                                    │ bob.local  │
                                    └────────────┘
```

## Key Concepts

### End-to-End Encryption

- All messages encrypted client-side with recipient's public key
- Server stores only encrypted blobs
- Even server admin cannot read message content

### Federation

- Servers discover each other via DNS/HTTPS
- Messages routed between servers automatically
- No central authority required

### Identity

- Each user has Ed25519 key pair
- Server attests user keys with digital signature
- Trust on first use (TOFU) for contacts

### First Contact

- Messages from unknown senders go to "requests" folder
- Recipient must accept before messages go to inbox
- Prevents unsolicited spam

## Folders

- **inbox**: Messages from accepted contacts
- **sent**: Messages you sent
- **requests**: First messages from unknown senders

## Troubleshooting

### Server won't start

Check config file is valid JSON:
```bash
cat config.json | jq .
```

Check ports are available:
```bash
lsof -i :8443
lsof -i :8080
```

### Client can't connect

Ensure server is running and check address:
```bash
curl http://localhost:8080/.well-known/mailx-server
```

### Message delivery failed

Check server logs for errors. For demo:
```bash
docker-compose logs server-a
```

For local server, check stdout.

## Next Steps

1. **Try the demo** - See [demo/README.md](demo/README.md)
2. **Read the docs** - See [docs/Architecture.md](docs/Architecture.md)
3. **Explore the code** - Start with [server/cmd/server/main.go](server/cmd/server/main.go)
4. **Join development** - See [docs/Roadmap.md](docs/Roadmap.md)

## Security Notes

⚠️ **This is demo software**:

- Not audited by security professionals
- Simplified password hashing (TODO: bcrypt)
- No TLS in demo (use `--insecure` flag for testing only)
- No rate limiting enforced yet

See [docs/ThreatModel.md](docs/ThreatModel.md) for complete security analysis.

## Getting Help

- **Issues**: https://github.com/albahrani/mailx/issues
- **Docs**: See `/docs` directory
- **Demo**: See `/demo/README.md`

## License

[See LICENSE file]
