# Roadmap - MailX

## Vision

Build a self-hostable, federated email replacement with end-to-end encryption by default, familiar `name@domain` addresses, and a clear path from demo to production.

## Canonical PRD

The umbrella PRD lives in [GitHub issue #2](https://github.com/albahrani/mailx/issues/2).

## Guiding Principles

1. Privacy first: E2EE by default and minimal metadata exposure.
2. Self-hosting first: easy to run without a central provider.
3. Email-like, not messenger-like: keep the product focused on mail semantics.
4. CLI-first now: native mobile later, web later still.
5. Documented, testable behavior: keep protocol, architecture, and threat model explicit.

## Current Scope

- No persistent groups or shared group keys.
- Multi-recipient delivery stays email-style fan-out.
- First-contact messages land in Requests until accepted or rejected.
- Alpha should harden strict TLS verification, key transparency, auth, sync, and rate limiting.
- Migration/import-export is allowed; a live email gateway is out of scope.
- Push notifications stay out for now.

## Milestones

### Demo v0.1

Status: Complete

Goal: prove the core flow.

Shipped:
- server and CLI client
- E2EE by default
- well-known discovery
- first-contact accept/reject flow
- Docker demo environment

### Alpha v0.2

Status: Planned

Goal: harden trust, auth, federation, and sync.

Focus:
- strict TLS verification
- basic key transparency
- device enrollment and revocation
- bounded local cache and sync
- rate limiting and quotas
- SQLite-first self-hosting

### Beta v0.8

Status: Planned

Goal: privacy and operational hardening.

Focus:
- forward secrecy
- subject encryption
- stronger federation verification
- attachment cache opt-in
- export/import and migration tools
- external security audit

### v1.0

Status: Planned

Goal: stable production release.

Focus:
- polish and performance
- multiple client implementations
- operational hardening
- comprehensive documentation
- broad adoption and supportability

## Notes

- This roadmap is intentionally concise; issue #2 is the detailed PRD.
- Architecture, Protocol, and Threat Model are the technical deep dives.
