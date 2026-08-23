# Security Policy

## Supported version

Security fixes are currently prepared for the `1.1.x` line. This repository is
not yet published; the policy takes effect with the first public release.

## Reporting a vulnerability

Use GitHub Private Vulnerability Reporting when it becomes available for the
repository. Until then, contact the maintainer through a private channel.

Do not include credentials, API tokens, private reports, sessions, wordlists,
personal data, or information about third-party targets in a public issue.
Reports should contain the smallest synthetic reproduction possible, affected
version, impact, and suggested mitigation.

The maintainers will acknowledge receipt, validate the report in an isolated
environment, and coordinate remediation before public disclosure. No response
time is guaranteed at this stage.

## Scope

In scope:

- leakage of secrets through configuration, sessions, logs, or reports;
- unsafe file handling or path traversal;
- unintended network activity in offline mode;
- dependency or installation-chain compromise;
- bypass of safety and output-sanitization controls.

Out of scope:

- testing against systems without written authorization;
- reports containing real credentials or personal data;
- availability or behavior of third-party APIs;
- issues caused solely by locally supplied datasets or wordlists.

See [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md) and [PRIVACY.md](PRIVACY.md).
