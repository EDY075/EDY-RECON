# Third-Party Notices

EDY RECON source code is released under the MIT License. That license does not
relicense third-party packages, datasets, services, or wordlists.

## Direct Python dependencies

| Package | Requirement | License observed locally | Project |
|---|---|---|---|
| Requests | `requests>=2.31.0` | Apache-2.0 | <https://requests.readthedocs.io/> |
| Paramiko | `paramiko>=3.3.0` | LGPL-2.1 | <https://www.paramiko.org/> |
| Colorama | `colorama>=0.4.6` | BSD-3-Clause | <https://github.com/tartley/colorama> |
| dnspython | `dnspython>=2.6.1,<3` | ISC | <https://www.dnspython.org/> |

## Transitive dependencies observed in the validated environment

These packages were installed locally during validation. Exact versions can
vary because the public requirements specify compatible ranges.

| Package | License observed locally |
|---|---|
| bcrypt | Apache-2.0 |
| cffi | MIT-0 |
| cryptography | Apache-2.0 OR BSD-3-Clause |
| PyNaCl | Apache-2.0 |
| urllib3 | MIT |
| certifi | MPL-2.0 |
| idna | BSD-3-Clause |
| charset-normalizer | MIT |
| pycparser | BSD-3-Clause |

Refer to each installed distribution for its complete license text and notices.

## External services

The application can optionally interact with services documented in the
README. Their APIs, responses, trademarks, and data remain subject to their own
terms. No external API account or token is included in the public repository.

## Datasets and wordlists

The MIT License applies only to the EDY RECON code and documentation created for
this repository. Local datasets and wordlists are excluded. See
[DATA_SOURCES.md](DATA_SOURCES.md) for the redistribution gate.
