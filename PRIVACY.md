# Privacy

EDY RECON is a local command-line tool. The project does not intentionally add
telemetry or a central collection service.

## Local data

Depending on the operator's actions, the application can create or update:

- `data/config.json`, containing local preferences and optional credentials;
- `sessions/`, containing investigation state;
- `reports/`, containing TXT or HTML outputs;
- `logs/`, containing local operational messages;
- locally downloaded datasets and wordlists.

These paths are excluded from the public release. The operator controls their
retention and must protect or securely delete them according to applicable law
and organizational policy.

## Third-party services

Network integrations are optional and run only when the operator selects the
corresponding function. A provider may receive the query required for that
operation. Before using a provider, review its privacy policy, terms, cost,
retention, and jurisdiction. Do not submit data without a lawful basis and
authorization.

AI integrations can transmit prompts or selected analysis content to the
configured provider. Use synthetic or approved data and apply data-minimization
rules. Local or offline operation is preferred for sensitive material.

## Credentials

Credentials are stored locally in `data/config.json`; the file must never be
committed, attached to issues, or included in reports. The public example uses
empty values. Revoke a credential immediately if exposure is suspected.

## Reports and sessions

The code sanitizes known password and secret fields before persistence, but
reports and sessions may still contain targets, e-mail addresses, domains, IP
addresses, findings, or other sensitive context. Treat every generated artifact
as private by default.

See [SECURITY.md](SECURITY.md) for private vulnerability reporting.
