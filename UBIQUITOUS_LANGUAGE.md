# Ubiquitous Language

This first pass is based on the repository docs, the umbrella PRD in GitHub issue #2, and the current issue set (#3 through #14). It is intentionally opinionated: where the sources use multiple words for the same concept, this glossary picks one canonical term and lists the others as aliases to avoid.

## Product and mailbox lifecycle

| Term | Definition | Aliases to avoid |
|------|-----------|-----------------|
| **MailX** | The federated, self-hostable email replacement product and protocol ecosystem. | mailx, mail system, messaging app |
| **Message** | One mail item with encrypted content, metadata, and optional attachments. | mail, email, note |
| **Mailbox** | The store that holds an account's folders and messages. | account data, inbox |
| **Folder** | A named subset of a mailbox used to organize messages. | bucket, queue |
| **Inbox** | The folder for messages from accepted senders. | mail, accepted folder |
| **Requests** | The folder for first-contact messages from unknown senders. | spam folder, request queue |
| **Sent** | The folder for messages sent from the account. | outbox, sent mail |
| **First-contact** | The initial exchange with an unknown sender before that sender is trusted. | new sender, first message |
| **Accept** | The action that moves a sender from first contact into trusted delivery. | approve, allow |
| **Reject** | The action that declines a first-contact request and stops that sender's future delivery. | delete, ignore |
| **Block** | The rule that prevents future delivery from a sender. | ban, mute |
| **Sender** | The account that originates a message. | author, from |
| **Recipient** | The account that is addressed by a message copy. | addressee, to |
| **Fan-out** | One send operation that creates separate per-recipient copies. | group send, broadcast |
| **To/Cc/Bcc** | Recipient visibility labels that apply to each copy in a fan-out send. | shared recipients, group members |
| **Message envelope** | The signed wrapper around an encrypted message that carries routing metadata. | envelope, payload wrapper |
| **Delivery** | The act of moving a message from one server to another. | transfer, send |
| **Retryable delivery** | Delivery that is retried after transient failure. | resend, redelivery |
| **Outbox** | The queue of messages waiting to be delivered or retried. | pending mail, send queue |
| **Dead letter queue** | The holding area for deliveries that exhausted retries. | failed mail queue |
| **Quota** | A storage or delivery limit that protects server resources. | allowance, limit |
| **Rate limit** | A cap on request or delivery frequency. | throttle, API limit |

## Identity, trust, and federation

| Term | Definition | Aliases to avoid |
|------|-----------|-----------------|
| **Domain** | The DNS namespace that owns a MailX identity and trust root. | server domain, host |
| **Account** | The authenticated mailbox identity bound to one `name@domain` address. | user, login, profile |
| **Address** | The `name@domain` identifier used to route and identify mail. | username, email address |
| **Operator** | The person or organization that runs a MailX server for a domain. | admin, owner, host |
| **Server** | The MailX deployment that routes messages and exposes APIs for one domain. | node, instance |
| **Federation** | MailX delivery between domains without a central provider. | server-to-server mail, inter-server mail |
| **Discovery** | The process of finding a peer server's metadata, endpoint, and keys. | lookup, peer discovery |
| **Well-known endpoint** | The `/.well-known/mailx-server` JSON record that advertises server metadata. | server info endpoint |
| **Trust anchor** | The root key used to verify a domain's published identity data. | root key, primary trust root |
| **Domain signing key** | The Ed25519 key a domain publishes to attest server info and user keys. | server signing key, domain key, signKey |
| **Server encryption key** | The X25519 key a server publishes for encrypted transport and delivery. | server public key, publicKey |
| **User encryption key** | The long-term key pair used to encrypt and decrypt message content for an account. | user key, mailbox key |
| **Server attestation** | The server signature that binds a user key to an address. | user signature, key binding |
| **Key directory** | The distributed key-discovery surface that publishes and verifies user keys. | key lookup service |
| **Key transparency log** | The append-only history of key registrations, rotations, and revocations. | key history log, Merkle log |
| **Strict TLS verification** | Certificate validation that fails closed instead of accepting insecure fallback. | relaxed TLS, skip verification |
| **mTLS** | Mutual TLS between servers, used as a later hardening step. | client certificate auth |
| **Peer authorization** | The extra check that authorizes a remote server after transport is established. | peer auth |
| **Anti-enumeration** | Design that makes it hard to discover valid users or keys by probing the system. | user enumeration prevention |

## Authentication and recovery

| Term | Definition | Aliases to avoid |
|------|-----------|-----------------|
| **Device** | A trusted client endpoint that can access an account. | handset, client |
| **Device key** | The key pair bound to a specific device for login, enrollment, and revocation. | user key, login key |
| **Passkey** | A platform-backed login credential that can satisfy the primary auth path. | passwordless login |
| **Session** | The time-bounded authenticated state for one device or client. | login session |
| **Access token** | The short-lived credential the client sends with API calls. | auth token, bearer token |
| **Refresh token** | The longer-lived credential used to mint a new access token. | long-lived token |
| **Password fallback** | Password login used when the primary device-based path is unavailable. | backup login |
| **Recovery key** | The secret that restores access after trusted devices are lost. | backup code, recovery code |
| **QR enrollment** | The QR-based process that adds a new trusted device. | device pairing, scan-to-enroll |
| **Revocation** | The act of removing a device's trusted access. | deauthorization, remote logout |

## Sync and offline use

| Term | Definition | Aliases to avoid |
|------|-----------|-----------------|
| **Mailbox state** | The read state and folder state that must stay consistent across devices. | sync state |
| **Version vector** | The sync structure used to merge mailbox state across devices. | version clock, sync counter |
| **Local cache** | The on-device store of messages and metadata used for offline access. | cache, offline store |
| **Bounded local cache** | A local cache with automatic expiry or size limits. | unlimited cache |
| **Attachment cache** | Local storage for attachments. | file cache |
| **Attachment cache opt-in** | The setting that keeps attachment caching off until enabled. | cache attachments by default |
| **Read state** | Whether a message has been read on a device. | seen state |
| **Folder state** | Which messages belong to which folder on a device. | mailbox contents |
| **Local search** | Search that runs only against cached content on the device. | server search, remote search |

## Client presentation and migration

| Term | Definition | Aliases to avoid |
|------|-----------|-----------------|
| **Compose** | The act of creating a new message. | write, draft |
| **Plain text** | Unformatted message content. | rich text |
| **Limited Markdown** | A constrained formatting subset allowed in composition. | Markdown, rich text |
| **Generic notifications** | Notifications that hide sender and subject details by default. | rich notifications |
| **Read receipt** | An explicit acknowledgment that a message was read. | delivery receipt |
| **Migration** | Moving data between systems without a live gateway. | transfer, move |
| **Import/export** | Tooling that moves mailbox snapshots and standard mail formats in and out of MailX. | backup/restore, data export |
| **Live email gateway** | A bridge to SMTP/IMAP or traditional email providers. | email bridge, gateway |
| **SMTP** | The legacy mail transport protocol MailX does not use as a live gateway. | email transport |
| **IMAP** | The legacy mailbox access protocol MailX does not use as a live gateway. | email access |

## Security and future protections

| Term | Definition | Aliases to avoid |
|------|-----------|-----------------|
| **End-to-end encryption** | Encryption that keeps message content readable only by sender and intended recipients. | E2EE |
| **Subject encryption** | The planned beta change that hides message subjects from servers. | encrypted subject |
| **Forward secrecy** | The property that past messages stay safe even if a current key is compromised later. | FS |
| **Sender-signed envelope** | The planned signed message wrapper that adds authenticity beyond transport security. | signed envelope |

## Relationships

- A **Domain** publishes one **Domain signing key**.
- A **Domain** can have one or more **Servers**.
- A **Server** attests one or more **Accounts**.
- An **Account** owns one **Mailbox**.
- A **Mailbox** contains multiple **Folders**, including **Inbox**, **Sent**, and **Requests**.
- A **Sender** can fan out one **Message** to one or more **Recipients**.
- A **Recipient** may become a **Sender** on a later message.
- A **Device** belongs to one **Account** and can be revoked.
- A **Recovery key** can restore one **Account** after trusted devices are lost.
- A **Version vector** tracks **Mailbox state** across multiple **Devices**.
- A **First-contact** message lands in **Requests** until the recipient **Accepts** or **Rejects** it.
- A **Reject** usually results in a **Block** for future delivery from that sender.
- A **Message** may be retried and eventually moved to a **Dead letter queue** if delivery keeps failing.

## Flagged ambiguities

- `user` is overloaded in the docs: sometimes it means the human, and sometimes it means the authenticated mailbox identity. Prefer **Account** for the mailbox identity and reserve `user` for generic role wording.
- `server signing key`, `domain key`, and `signKey` all refer to the same trust anchor. Prefer **Domain signing key**.
- `user key`, `user encryption key`, and `device key` refer to different things across the docs. Prefer **User encryption key** for message crypto and **Device key** for authentication and enrollment.
- `mail`, `message`, and `email` are used interchangeably. Prefer **Message** for the content object.
- `Requests` is used both as a folder and as a workflow name. Prefer **Requests** for the folder and **First-contact** for the workflow.
- `reject` and `block` overlap in the first-contact flow. Prefer **Reject** for the user action and **Block** for the ongoing rule.
- `domain`, `server`, and `operator` can blur together. In this glossary, **Domain** is the identity namespace, **Server** is the runtime deployment, and **Operator** is the human or organization running it.

## Example dialogue

> **Dev:** "If Bob sends Alice a first message, does it go straight to Alice's Inbox?"
>
> **Domain expert:** "No, it lands in **Requests** until Alice **Accepts** Bob."
>
> **Dev:** "And if Alice **Rejects** it?"
>
> **Domain expert:** "Then Bob is **Blocked**, so future messages stay out."
>
> **Dev:** "When Bob sends to Alice and Carol at once, do we create a group?"
>
> **Domain expert:** "No, that's **Fan-out**: one **Message**, separate copies, no persistent group."
>
> **Dev:** "What key do other servers trust?"
>
> **Domain expert:** "The **Domain signing key**, not the device key."

## Sources considered

- `README.md`
- `QUICKSTART.md`
- `docs/index.md`
- `docs/overview.md`
- `docs/Architecture.md`
- `docs/Protocol.md`
- `docs/ThreatModel.md`
- `docs/Roadmap.md`
- `demo/README.md`
- GitHub issue `#2`
- GitHub issues `#3` through `#14`
