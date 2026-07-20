# Security Policy

## Supported Versions

Only the latest released version receives security updates.

| Version | Supported |
| ------- | --------- |
| Latest  | Yes       |

## Reporting a Vulnerability

If you believe you have found a security issue in Cipher, please report it privately to the maintainers rather than opening a public issue.

Cipher is a local file encryption and decryption service that involves:
- **Fernet key management** — creating, storing, and using symmetric key files for encryption and decryption
- **File transformation** — processing file encryption and decryption in background threads with chunked streaming
- **Path validation** — enforcing allowlist and blacklist policies for directories accessible to the service
- **Filename encryption** — optionally encrypting or decrypting file names alongside content
- **Background task processing** — queuing and cleaning up encryption and decryption jobs
- **ServiceHandler integration** — optional registration for service discovery and endpoint registration

Include as much detail as possible, such as:
- A clear description of the issue and the affected component (key creation, encryption, decryption, path validation, task management)
- Steps to reproduce the problem, including relevant file paths, key locations, and configuration settings
- Whether the issue could expose encrypted data, leak key material, or bypass path restrictions
- Any relevant logs, error messages, or proof of concept code

If the report involves key files, encrypted data, or configuration secrets, redact sensitive values before sharing.

## What To Expect

After a report is received:

1. The issue will be reviewed and triaged.
2. You may be contacted for clarification or additional details.
3. A fix may be developed and validated before public disclosure.
4. The reporter may be credited unless they prefer to remain anonymous.

## Security Guidelines

This project is intended to follow basic security hygiene:

- **Fernet key storage** — Keys are stored as plain files on disk. Protect key file directories with appropriate filesystem permissions. Losing a key makes encrypted data permanently unrecoverable.
- **Localhost binding** — The service binds to `127.0.0.1:49158` and rejects all non-local requests. Verify that the service is never exposed to a network interface.
- **Path validation** — All file paths are resolved and checked against the allowlist and blacklist policy before any operation proceeds. Review your path policy carefully; an empty allowlist permits all paths on the system.
- **File access controls** — The service runs with the permissions of the invoking user. Restrict the service account to the minimum set of directories needed.
- **Background task isolation** — Encryption and decryption run in background threads with no external input after queuing. Finished tasks are cleaned up after a configurable retention period.
- **Dependency review** — Regularly review dependencies (Flask, cryptography) for known vulnerabilities. Pin versions in `requirements.txt`.
- **Key file protection** — The API prevents the key file from being used as an input or output file during encryption or decryption operations, protecting it from accidental corruption.
- **Treat all externally supplied input as untrusted** and validate it before use. The API validates file paths, key files, and configuration values across all endpoints.

## Disclosure Notes

Do not publicly disclose an unpatched vulnerability until maintainers have had reasonable time to investigate and respond. If a coordinated disclosure timeline is needed, it can be discussed during the report process.
