# Robot Security SOC

[![Security Tests](https://github.com/S3rgiu12/robot-security-soc/actions/workflows/security-tests.yml/badge.svg)](https://github.com/S3rgiu12/robot-security-soc/actions/workflows/security-tests.yml)

A hands-on Cybersecurity and Robotics Security portfolio project
focused on secure robot telemetry, intrusion detection, incident
investigation, digital evidence integrity, and SOC monitoring.

## System Architecture

High-level overview of the Robot Security SOC components.

```mermaid
flowchart TD
    A["Robot Telemetry"] --> B["TLS 1.3 Communication"]
    B --> C["IDS & Security Monitoring"]
    C --> D["Flask SOC Dashboard"]
    D --> E["Incident Investigation & Reporting"]
    E --> F["SHA-256 Evidence Integrity"]
    F --> G["Ed25519 Signature Verification"]
```

This diagram shows the conceptual security architecture.

## Technology Stack

- Python 3
- Flask
- TLS 1.3
- SQLite
- Ed25519 digital signatures
- SHA-256 integrity verification
- HTML, CSS, JavaScript
- Ubuntu 24.04 / WSL2

## Project Overview

The project evolves through practical security engineering exercises,
starting with robot telemetry and network monitoring and progressing
toward incident investigation and cryptographic evidence verification.

Key implemented components include:

- Secure robot telemetry communication
- TLS-encrypted client/server communication
- Intrusion detection and alert monitoring
- Flask-based SOC dashboard
- IDS heartbeat monitoring
- Analyst authentication and authorization
- Incident investigation and reporting
- Evidence integrity verification
- Digitally signed incident report bundles

## Day 28 - Digital Signatures & Incident Integrity

Day 28 introduces Ed25519 detached digital signatures for incident
report manifests, combined with SHA-256 verification of exported
evidence files.

### Security Features

- Ed25519 signing and signature verification
- Encrypted private key storage
- Trusted public key fingerprint verification
- SHA-256 integrity verification
- Secure file access with symlink protection
- Authenticated Flask verification API
- SOC dashboard signature verification interface

### Verification Results

The following security scenarios were tested successfully:

| Security Test | Result |
| --- | --- |
| Tampered manifest detection | PASS |
| Tampered evidence detection | PASS |
| Forged signature rejection | PASS |
| Symbolic link rejection | PASS |

The final verification of the original incident bundle confirmed:

- Ed25519 signature: VALID
- SHA-256 integrity: VALID
- Verified evidence files: 3/3
- Overall status: SIGNED & VERIFIED

These results demonstrate the tested scenarios, not a complete
security audit or production certification.

## Project Structure

- `day06/` - Flask SOC dashboard
- `day18/` - Analyst authentication
- `day25/` - Incident case management
- `day26/` - Incident reporting
- `day27/` - Report integrity verification
- `day28/` - Digital signatures and secure verification

## Security and Privacy

Private keys, environment files, operational databases,
generated evidence exports, and runtime artifacts are excluded
from version control.

Never commit real credentials or private signing keys.

The project is intended for educational and portfolio purposes.
Deployment requires additional configuration, security review,
and environment-specific hardening.

## Author

Sergiu Dumitrasc

Cybersecurity | Robotics Security | Software Development
