# Client PRD - MailX Secure Email Client

## Overview
The MailX client provides a user interface for the secure email replacement system. It handles local key management, end-to-end encryption, and communication with the user's MailX server while ensuring privacy and security.

## 1. Account Setup

### 1.1 Account Registration
- **New Account Creation**: Register on a MailX server
  - Input: server address, desired username, password
  - Generate local encryption key pair (NaCl box / X25519)
  - Submit public key to server for attestation
  - Store credentials securely in local keychain/keyring
- **Account Import**: Import existing account on new device
  - Requires recovery key or device-to-device transfer
  - Re-download message metadata from server
- **Multi-Server Support**: Connect to multiple MailX accounts
  - Switch between accounts seamlessly
  - Unified inbox view (optional)

### 1.2 Initial Configuration
- **Profile Setup**: Display name, profile picture (optional)
  - Profile data stored locally, not on server
  - Can be shared per-contact via message headers
- **Server Connection**: Configure server endpoint
  - Auto-discovery via domain name
  - Manual configuration fallback
- **Preferences**: Set default preferences
  - Message retention, notification settings
  - Theme, language

## 2. Key Management

### 2.1 Identity Keys
- **Key Generation**: Generate NaCl box (X25519) key pair on first run
  - Private key never leaves device (or encrypted backup)
  - Public key registered with server
- **Key Storage**: Secure local storage
  - OS keychain on macOS (Keychain)
  - Secret Service on Linux (gnome-keyring, kwallet)
  - DPAPI on Windows
  - Encrypted file fallback with master password
- **Recovery Key**: Generate recovery key for account backup
  - BIP39 mnemonic (24 words)
  - Print or save securely
  - Can restore account on new device

### 2.2 Contact Keys
- **Key Discovery**: Fetch recipient public keys from their server
  - Cache keys locally
  - Verify server attestation signature
  - Display key fingerprint for manual verification
- **Trust Management**: Trust on first use (TOFU) model
  - First contact: display key fingerprint, option to verify
  - Key change: warn user, require explicit trust
  - Manual verification: Compare fingerprint via side channel
- **Key Pinning**: Pin trusted contact keys
  - Reject messages from same address with different key
  - Unless key rotation is properly signed

### 2.3 Key Rotation
- **Planned Rotation**: User-initiated key rotation
  - Generate new key pair
  - Notify server and all contacts
  - Keep old key for decrypting archived messages
- **Emergency Rotation**: Compromise response
  - Revoke old key immediately
  - Broadcast revocation to contacts
  - Re-encrypt critical messages with new key

## 3. Multi-Device Support

### 3.1 Device Management
- **Device Registration**: Register multiple devices per account
  - Each device has its own key pair
  - Server stores all device keys
  - Messages encrypted for all devices
- **Device List**: View and manage registered devices
  - Device name, type, last active
  - Revoke device access remotely
- **Primary Device**: Designate one primary device
  - Can manage other devices
  - Required for account recovery

### 3.2 Message Sync
- **Server-Side Storage**: Messages stored on server (encrypted)
  - Download messages to all devices
  - Mark as read/unread synced across devices
- **Sync Protocol**: Incremental sync
  - Only fetch new/changed messages
  - Version vectors for conflict resolution
- **Offline Access**: Local message cache
  - Full text search on cached messages
  - Queue outbound messages for later delivery

### 3.3 Device-to-Device Key Transfer
- **QR Code**: Display QR code on existing device
  - Scan with new device to transfer identity
  - Encrypted transfer with temporary session key
- **Verification**: Require physical access to both devices
  - Display verification code on both devices
  - Must match before completing transfer

## 4. User Experience

### 4.1 First Contact Workflow
- **Incoming Request**: Message from unknown sender
  - Display in "Requests" folder
  - Show sender identity: address + key fingerprint
  - Preview subject (metadata not encrypted)
- **Accept/Reject**: User action required
  - Accept: add to contacts, deliver message to inbox
  - Reject: delete message, optionally block sender
  - Auto-accept option for power users
- **Sending to New Contact**: First message to unknown recipient
  - Fetch recipient key from server
  - Display key fingerprint for verification
  - Option to verify via side channel before sending
  - Send with "first contact" flag

### 4.2 Composing Messages
- **Rich Text Editor**: Support basic formatting
  - Bold, italic, lists, links
  - No embedded images initially (privacy leak risk)
- **Attachments**: Support file attachments
  - Max size: 25 MB (configurable)
  - Encrypted with message
  - Display file type, size before download
- **Recipients**: Multiple recipients supported
  - To, Cc, Bcc fields
  - Each recipient message individually encrypted
  - Bcc recipients hidden from other recipients
- **Auto-Save**: Save draft locally
  - Encrypted with user's key
  - Auto-save every 30 seconds

### 4.3 Reading Messages
- **Inbox View**: List of received messages
  - Sender, subject, timestamp
  - Read/unread indicator
  - Star/flag for importance
- **Message View**: Full message display
  - Decrypt on demand
  - Show sender identity with trust indicator
  - (Planned) Verify sender signature
  - Display attachments with download option
- **Threading**: Group related messages
  - In-reply-to and references headers
  - Conversation view

### 4.4 Search and Organization

#### 4.4.1 Search
- **Metadata Search**: Fast search on server
  - Sender, recipient, subject, date range
  - Does not require decrypting message bodies
- **Full-Text Search**: Search message content
  - Client-side only (messages decrypted locally)
  - Build search index incrementally
  - Privacy-preserving (index never sent to server)
- **Search Filters**: Advanced filtering
  - Has attachments, is unread, is starred
  - From/to specific contact
  - Date range

#### 4.4.2 Folders
- **Default Folders**: Inbox, Sent, Requests, Archive, Trash
  - Cannot be deleted or renamed
- **Custom Folders**: User-created labels/folders
  - Apply to messages as tags
  - Messages can have multiple labels
  - Sync across devices
- **Smart Folders**: Dynamic searches saved as folders
  - Example: "Unread from last week"
  - Updates automatically

#### 4.4.3 Archiving
- **Archive Action**: Move message out of inbox
  - Keeps message searchable
  - Reduces inbox clutter
- **Bulk Operations**: Archive multiple messages
  - Select all, select by filter
- **Export**: Export messages to standard format
  - mbox or maildir format
  - Includes decrypted content
  - For backup or migration

## 5. Offline Support

### 5.1 Offline Reading
- **Message Cache**: Store recent messages locally
  - Decrypt and cache for offline access
  - Configurable cache size (default: 1000 messages)
- **Attachment Cache**: Optionally cache attachments
  - User can choose which to keep offline
- **Search Offline**: Use local search index
  - Limited to cached messages

### 5.2 Offline Composing
- **Draft Queue**: Compose messages while offline
  - Save to local queue
  - Auto-send when connection restored
- **Outbox**: Pending outbound messages
  - Show delivery status
  - Retry failed deliveries

### 5.3 Sync on Reconnect
- **Incremental Sync**: Fetch only new messages
  - Use last sync timestamp
- **Conflict Resolution**: Handle concurrent edits
  - Read/unread status, labels
  - Last-write-wins for simple fields
  - Merge labels (union)

## 6. Security & Privacy

### 6.1 End-to-End Encryption
- **Default E2EE**: All messages encrypted by default
  - No plaintext option
 - **Crypto Algorithm**: NaCl box (X25519 + XSalsa20-Poly1305) via Go `x/crypto/nacl/box`
  - Curve25519 for key exchange (if needed for groups)
  - Ed25519 for signatures
  - XSalsa20-Poly1305 for encryption
- **Metadata Protection**: Minimize metadata leakage
  - Subject encrypted in message body (future)
  - Timing correlation still possible

### 6.2 Local Security
- **Password Protection**: Require password to unlock client
  - Encrypts local key storage
  - Auto-lock after inactivity
- **Screen Lock**: Integrate with OS screen lock
  - Clear sensitive data from memory on lock
- **Clipboard Security**: Clear clipboard after paste
  - Time-limited clipboard content

### 6.3 Privacy Features
- **No Telemetry**: No analytics or tracking
  - No data sent to third parties
  - No crash reports unless user opts in
- **No Cloud Sync**: Keys never synced to cloud
  - Only explicit device-to-device transfer
- **Local-First**: All decryption client-side
  - Server never sees plaintext

## 7. Notifications

### 7.1 New Message Notifications
- **Desktop Notifications**: Show sender and subject
  - Respect OS notification settings
  - Option to hide sensitive info
- **Badge Count**: Unread message count
  - On app icon
- **Sound Alerts**: Configurable sound for new messages

### 7.2 Privacy in Notifications
- **Hide Content**: Option to show only "New message"
  - No sender or subject in notification
- **Disable Notifications**: Per-contact notification settings
  - Mute specific contacts or folders

## 8. Platforms

### 8.1 Desktop
- **Linux**: Native app (GTK or Qt)
  - Debian/Ubuntu package (.deb)
  - Flatpak for universal distribution
- **macOS**: Native Cocoa app
  - Distributed via GitHub releases
  - Future: Mac App Store
- **Windows**: Native app (Qt or Electron)
  - MSI installer

### 8.2 Mobile
- **iOS**: Native Swift app (future)
  - App Store distribution
- **Android**: Native Kotlin app (future)
  - F-Droid and Google Play

### 8.3 Web
- **Web Client**: Browser-based client (future)
  - WASM for crypto operations
  - Service worker for offline support
  - No server-side decryption

## 9. Accessibility

### 9.1 Keyboard Navigation
- **Full Keyboard Support**: Navigate entire UI with keyboard
  - Standard shortcuts (Ctrl+N for new, Ctrl+R for reply)
  - Vim-style shortcuts optional
- **Screen Reader**: Proper ARIA labels
  - Announce new messages
  - Read message content

### 9.2 Visual
- **High Contrast**: Support high contrast themes
- **Font Scaling**: Respect OS font size settings
- **Color Blindness**: Don't rely solely on color for information

## 10. Internationalization

### 10.1 Language Support
- **UI Translation**: Support multiple languages
  - English, Spanish, German, French, Chinese, Japanese (initial set)
  - Community translations welcome
- **RTL Support**: Right-to-left languages
  - Arabic, Hebrew

### 10.2 Locale Settings
- **Date/Time Format**: Use locale-specific formats
- **Number Format**: Respect locale conventions

## 11. Testing Requirements

### 11.1 Unit Tests
- Crypto functions (encrypt, decrypt, sign, verify)
- Key management operations
- Message parsing and formatting

### 11.2 UI Tests
- Message compose and send flow
- Contact trust workflow
- Search functionality

### 11.3 Integration Tests
- End-to-end message delivery
- Multi-device sync
- Offline/online transitions

## 12. Performance Goals

- **Startup Time**: < 2 seconds to ready state
- **Message Decrypt**: < 100ms per message
- **Search**: < 500ms for metadata search
- **UI Responsiveness**: 60 FPS scrolling, < 16ms frame time
- **Memory Usage**: < 200 MB for typical workload (1000 cached messages)

## 13. Success Metrics

- **User Adoption**: Track active users (opt-in analytics)
- **Message Volume**: Messages sent/received per user
- **Error Rate**: < 0.1% message delivery failures
- **Crash Rate**: < 0.01% crash rate per session
- **Security**: Zero critical vulnerabilities

## 14. Future Enhancements

- Voice and video calls (WebRTC)
- Group messaging with group keys
- Self-destructing messages
- Read receipts (optional)
- Typing indicators (optional)
- Rich message types (polls, locations)
- Bot integration API
- Plugin/extension system
