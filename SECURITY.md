# Security Policy

## Reporting a vulnerability

Please report a suspected vulnerability privately through the repository's GitHub **Security → Report a vulnerability** feature. Do not include secrets, personal data, production assessment evidence, or details that are unnecessary to reproduce the issue.

Allow a reasonable period for triage and remediation before public disclosure. Maintainers will acknowledge a report when possible, assess its impact, and coordinate next steps. Public issues are appropriate for non-sensitive defects and feature requests only.

## Security model

Sentinel Studio is a client-side reporting application:

- It makes no network requests and has no server component.
- It does not perform discovery, scanning, exploitation, or verification.
- Finding records are stored in browser local storage.
- JSON import is size-limited, schema-checked, and rendered through DOM text properties.
- External finding references open in a separate tab with opener isolation.
- Data exported or printed by a user may be sensitive and is outside the application's control.

Local storage is not encrypted and is accessible to users and software with access to the same browser profile. Do not store secrets, credentials, raw tokens, unnecessary personal data, or unredacted sensitive evidence. Use a managed assessment platform when organizational requirements call for encryption, access control, audit logging, retention enforcement, or multi-user workflows.

## Supported versions

Security fixes are applied to the latest version on the default branch. This static project does not maintain older release branches.

## Appropriate use

Use the dashboard only for authorized assessment documentation. Sample records are fictional and must not be represented as findings from a real organization.