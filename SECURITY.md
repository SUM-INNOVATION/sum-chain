# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report suspected vulnerabilities privately to the maintainers:

- Preferred: open a private report via GitHub's **"Report a vulnerability"**
  (Security → Advisories) on this repository, if enabled.
- Otherwise: contact the maintainers through a private channel rather than a
  public issue or pull request.

Please include enough detail to reproduce the issue (affected component,
version/commit, and steps). We will acknowledge the report and follow up on a
fix and disclosure timeline.

## Scope

This repository contains the SUM Chain node and its supporting crates, SDKs, and
tooling. Security-relevant areas include consensus, transaction execution,
cryptography, the RPC surface, and key handling. Please flag anything that could
affect chain integrity, fund safety, or node availability.

## Supported versions

The project is under active development; security fixes target the latest
`main`. There is no long-term-support branch at this time.
