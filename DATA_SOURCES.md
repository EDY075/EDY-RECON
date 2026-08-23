# Data Sources and Redistribution Status

The public repository distributes source code and synthetic examples only. It
does not distribute locally generated output, the current breach catalog, the
embedded password base, or downloaded wordlists.

## `data/breaches.json`

- Local state observed: valid JSON with 69 metadata records.
- Publication state: excluded by `.gitignore`.
- Provenance state: pending. The local file does not contain sufficiently
  granular URLs, authorship, access dates, or license evidence.
- Redistribution state: **not distributable / local use only** until provenance
  and redistribution rights are documented.

The 69 records were not edited or copied during publication preparation.

## Wordlists

Wordlists are downloaded and stored locally under `data/wordlists/`. The public
repository contains only the updater and
[`WORDLISTS_MANIFEST.csv`](WORDLISTS_MANIFEST.csv). The manifest records the
locally observed filename, purpose, declared URL, version/commit status,
license status, SHA-256, local timestamp, and redistribution decision without
copying wordlist contents.

An upstream URL or public availability does not by itself prove a right to
redistribute. Entries without verified license evidence are marked
**not distributable / local use only**.

## Synthetic data

Tests use documentation domains, reserved IP address ranges, and synthetic
credentials. No fixture is copied from `data/breaches.json`, reports, sessions,
configurations, or wordlists.

## Review gate

Before publishing any dataset:

1. identify the original publisher and canonical URL;
2. pin a version, release, or commit;
3. retain the license and required attribution;
4. record the SHA-256 and acquisition date;
5. review privacy, contract, and jurisdictional restrictions;
6. approve redistribution separately from the code release.
