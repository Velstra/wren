# Security Policy

Wren is a routing daemon: a bug can affect how traffic is forwarded, so we take
security reports seriously.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, use **GitHub's private vulnerability reporting**: open the repository's
**Security** tab → **Report a vulnerability**. This opens a private advisory only
the maintainers can see.

Please include:

- the affected component (crate / protocol / version or commit),
- a description of the issue and its impact,
- steps to reproduce, ideally a minimal config and topology,
- any suggested fix.

We aim to acknowledge a report within a few days and will coordinate a fix and a
disclosure timeline with you.

## Supported versions

Wren is pre-1.0 (`0.0.x`); only the latest `main` is supported. Once releases are
tagged, this section will list the supported version range.
