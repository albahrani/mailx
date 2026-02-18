---
title: Overview
description: What MailX is trying to fix, and how it feels.
---

# Overview

MailX is an attempt to keep the parts people love about email (addresses, domains, independence) while removing what makes it painful (spam, phishing, account takeovers, and constant trust in intermediaries).

## The Promise

- Your messages are end-to-end encrypted by default.
- Your address stays simple: `name@domain`.
- You can run your own server, or choose someone you trust.
- First-time senders do not land straight in your inbox.

## How It Feels

You send a message.

The recipient gets it, but if you are not yet trusted, it lands in Requests. One explicit accept, and future messages go to Inbox. No filters to tune. No surprise delivery of junk.

## What MailX Is (and Is Not)

- MailX is a federated messaging system with an open protocol.
- MailX is not a hosted service; it is a self-hostable project.

## Current Status

MailX is currently a demo/reference implementation.

- It is meant to be easy to understand and try.
- It is not production-ready.

If you want the technical details, head to:

- [Architecture]({{ "/Architecture/" | relative_url }})
- [Protocol]({{ "/Protocol/" | relative_url }})
- [Threat Model]({{ "/ThreatModel/" | relative_url }})

## Next

- Want to understand the system design? Read [Architecture]({{ "/Architecture/" | relative_url }}).
- Want the wire-level details? Read [Protocol]({{ "/Protocol/" | relative_url }}).
