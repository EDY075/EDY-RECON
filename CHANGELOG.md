# Changelog

All notable public changes will be documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Publication allowlist, private-file exclusions, release auditor, and offline CI.
- Security, privacy, acceptable-use, data-source, and third-party notices.
- Sanitized configuration examples and empty public output directories.

### Changed

- README reorganized for the first public release without bundling private
  datasets, generated artifacts, credentials, or wordlists.

## [1.1.0] - 2026-08-23

### Added

- Windows and Kali launchers, interactive menus, four terminal themes, OSINT,
  breach metadata, password checks, authorized credential-test workflows,
  optional AI providers, and TXT/HTML reports.
- Offline test suite covering containment, interface, reports, updater behavior,
  and password-field redaction.

### Security

- Atomic configuration/output writes and recursive sanitization of known secret
  fields before session and report persistence.
- Bounded retries, work queues, timeouts, and safer synchronization/install flows.

### Validation

- Windows/offline path validated with 40 tests. Kali portability, external APIs,
  AI providers, and real integrations remain outside the validated scope.
