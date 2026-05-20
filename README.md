# ia_logger — Intrusion and Activity Logger

**CS50P Final Project** | Python · SQLite · bcrypt · pyotp  
> A command-line employee authentication and anomaly detection system that simulates the security layer of an internal enterprise tool — logging intrusion events, enforcing 2FA, and maintaining a full audit trail.

---

## Overview

`ia_logger` models the authentication and activity monitoring layer of a system used in high-accountability environments — a bank, for instance. It is not a full HR or business system. It handles one specific domain deliberately: **who logged in, when, from where, under what conditions, and whether that should be trusted.**

It logs both normal activity (session time-ins and outs, password changes, email updates) and anomalous events (repeated failed logins, geographic location changes, suspicious IPs, off-schedule access, OTP replay attempts). On the defensive side, it enforces bcrypt password hashing, TOTP-based two-factor authentication, session blacklisting, and role-based access control.

The system is self-contained and does not interact with any live data. It does not touch client or consumer records — only employee-side authentication and activity.

---

## Features

### Authentication & Session Management
- Multi-step login: work email → bcrypt-verified password → TOTP code
- Session timestamping on login and logout, both requiring full authentication
- Auto-logout for accounts past their scheduled shift window or flagged during active sessions
- Session blacklisting to invalidate active tokens on security events

### Anomaly Detection & Intrusion Logging
- **Failed login tracking** — consecutive and cumulative failure counts trigger account locks
- **Geographic location change detection** — flags logins from a country different from the account's verified location
- **Off-schedule access** — detects logins outside the user's configured work schedule
- **Suspicious IP detection** — cross-references against a trusted network range table and a blacklist
- **TOTP replay prevention** — used OTPs are stored and rejected within the same time window
- **Credential stuffing detection scaffolding** — blacklisted IPs force-logout any active session that used them

All anomalies are written to `security_events_logs` with full context. The system applies a **composite security scoring model** — multiple signals stack to determine lock thresholds, rather than any single trigger acting alone.

### Audit Trail
Every entity change — user status transitions, schedule updates, session records, network and blacklist modifications — is mirrored to a corresponding log table. Log tables have no enforced foreign key relationships to their parent tables by design: deleted records remain preserved in the audit trail.

### User Commands
- `login` — authenticate and begin a session
- `logout` — end session with authentication
- `activate` — first-time account activation using a temporary password and token
- `change-password` — update password while logged in
- `change-email` — update personal email on record

### Admin Commands
- `register` — create a new employee account, generate credentials
- `lock` / `unlock` — manual account locking and unlocking with notes
- `terminate` — permanently disable an account
- `set-schedule` — configure work days and shift time windows per user
- `change-location` — update a user's verified country (e.g. international branch transfer)
- `blacklist` — manually blacklist an IP or personal email
- `find-user` — look up a user by work email
- `fetch-info` — retrieve extended account details
- `gen-token` — manually generate a new activation or unlock token
- `gen-temp-password` — reset and reissue a temporary password

Admins must be authenticated to perform any admin-only command. Role separation is enforced at the command level.

---

## Tech Stack

| Component | Detail |
|---|---|
| Language | Python 3 |
| Database | SQLite (via `sqlite3`) |
| Password hashing | `bcrypt` |
| Two-factor auth | `pyotp` (TOTP — RFC 6238) |
| IP/geo lookup | `requests` + external API |
| Testing | `pytest` |

---

## Project Structure

```
ia_logger/
├── logger/
    ├── data/
        └── ia_logger.db        # Pre-seeded database for testing
    ├── ia_logger.py            # Entry point and CLI command routing
    ├── schema.sql              # Full database schema
    └── sample_query.sql        # Dummy data for testing and querying
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Setup & Usage

### Requirements

```
Python 3.10+
```

Install dependencies:

```bash
pip install -r requirements.txt
```

### Running

```bash
python ia_logger.py <command> [options]
```

Examples:

```bash
python ia_logger.py login
python ia_logger.py register
python ia_logger.py set-schedule --user employee@company.com
```

The database comes pre-seeded with test accounts across user and admin roles. TOTP codes, activation tokens, and temporary passwords are printed to the terminal during demos — in a real deployment these would be delivered through a secure medium.

### Running Tests

```bash
pytest test_project.py
```

---

## Database Schema (Summary)

Eight core tables, five audit log tables.

| Table | Purpose |
|---|---|
| `users` | All employee accounts and authentication data |
| `users_schedule` | Per-user shift windows and work day configuration |
| `user_sessions` | Session time-in/out records with IP and location |
| `login_attempts_logs` | All login attempts, success and failure, with failure reasons |
| `security_events_logs` | Detected anomalies and intrusion events |
| `trusted_networks` | Company IP ranges for network validation |
| `blacklist` | Blacklisted IPs and personal emails |
| `used_totps` | OTP replay prevention table |
| `*_logs` | Audit trail tables for all entity changes |

Full schema: [`schema.sql`](schema.sql) | ERD: [`erd.png`](erd.png)

---

## Design Decisions & Scope

**SQLite as the database** — chosen for portability and self-containment. SQLite lacks built-in user authentication and row-level security, so all access control is handled at the application layer. This is a known tradeoff for a single-process demonstration system; a production equivalent would use PostgreSQL or similar with proper privilege separation.

**Audit log foreign key design** — log tables deliberately omit foreign key constraints back to their parent tables. This preserves deleted or terminated account records in the audit trail, which is the point of having one.

**TOTP delivered to terminal** — in production, TOTP secrets and temporary credentials would be delivered via a secure channel (email, authenticator app). Terminal output is used here for demonstration only.

**Scope boundaries held deliberately** — `ia_logger` does not model HR workflows (batch registration, org structure, leave), break/overtime scheduling, or client-side transaction auditing. These are outside its domain. The system does one thing: authenticate employees and log everything that happens around that process.

---

## Background

This project was built as the final project for [CS50P](https://cs50.harvard.edu/python/) (Harvard's Introduction to Programming with Python). It draws from prior experience in telecom authentication and fraud operations, and is part of a broader portfolio targeting security analyst and SOC roles.

Related project: [SIREN](https://github.com/flyingKatze/siren) — a crowdsourced spam/scam number tracking database for the Philippine telecom context (CS50 SQL final project).

---

## Author
[GitHub](https://github.com/flyingKatze) · [GitLab](https://gitlab.com/flyingKatze)
