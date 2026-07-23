# Secure Banking System Prototype

Flask + SQLite banking demo for the security assignment (algorithm, protocol, and system-level controls).

Runs well on **Rocky Linux** (VMware VM) or any Linux/macOS host with Python 3.9+.

---

## Features

| Area | What is implemented |
|------|---------------------|
| Login / sessions | Flask-Login, bcrypt passwords, 15-min idle timeout, HttpOnly cookies |
| Dashboard | Balance snapshot, masked account number, role display |
| View balance | AES-256-GCM decrypt of stored account number |
| Transfer | Balance update + SHA-256 payload hash + RSA-PSS digital signature |
| History | Re-verifies every signature on page load |
| Admin | Role-based access; audit log viewer |
| HTTPS | Self-signed TLS certificate (auto-generated on first run) |
| Backup | `backup.py` / `backup.sh` copies `bank.db` + SHA-256 checksum |

---

## Project layout

```
Banking-Sys-prototype/
├── app.py                 # Main Flask application
├── backup.py / backup.sh  # System-level DB backup
├── requirements.txt
├── bank.db                # Created on first run
├── crypto/
│   ├── hashing.py         # bcrypt + SHA-256
│   ├── aes.py             # AES-256-GCM
│   └── rsa.py             # RSA-2048 keypair + PSS signatures
├── templates/             # HTML (Bootstrap)
├── static/css/style.css
├── keys/                  # AES key + RSA PEM (auto-created)
├── certificates/          # TLS cert/key (auto-created)
├── logs/audit.log         # Append-only audit trail
└── backups/               # Timestamped DB copies
```

---

## How to run (Rocky Linux / Linux)

### 1. Install system packages (Rocky Linux)

```bash
sudo dnf install -y python3 python3-pip python3-devel gcc openssl
```

### 2. Go to the project folder

```bash
cd /path/to/prototype/Banking-Sys-prototype
```

### 3. Create a virtual environment and install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 4. Start the server (HTTPS by default)

```bash
python3 app.py
```

Open in a browser:

```
https://127.0.0.1:8443
```

- The first run creates `bank.db`, crypto keys, TLS cert, and demo users.
- The browser will warn about the **self-signed certificate** — choose Advanced → Proceed (expected for a lab prototype).

### 5. Optional: run over plain HTTP (lab only)

```bash
BANK_HTTPS=0 BANK_PORT=5000 python3 app.py
```

Then open `http://127.0.0.1:5000`.

### 6. Backup the database

```bash
chmod +x backup.sh
./backup.sh
# or: python3 backup.py
```

Backups appear under `backups/` as `bank_YYYYMMDD_HHMMSS.db` plus a `.sha256` checksum file.

---

## Demo accounts

| Username | Password   | Role  | Starting balance |
|----------|------------|-------|------------------|
| alice    | Alice@123  | user  | $5000.00         |
| bob      | Bob@12345  | user  | $2500.00         |
| admin    | Admin@123  | admin | $10000.00        |

Suggested demo flow:

1. Login as **alice**
2. Open **Balance** (shows decrypted account number)
3. **Transfer** $100 to **bob**
4. Open **History** — signature column should show **Valid**
5. Logout, login as **admin**, open **Audit Logs**

---

## Security mapping (assignment Part 2)

### a) Algorithm level

| Mechanism | Where used | Module |
|-----------|------------|--------|
| **bcrypt** (salted password hashing) | User passwords at rest | `crypto/hashing.py` |
| **AES-256-GCM** (symmetric encryption) | Account numbers in DB | `crypto/aes.py` |
| **SHA-256** hashing | Transaction payload digest | `crypto/hashing.py` |
| **RSA-2048 + PSS** (asymmetric digital signature) | Sign / verify each transfer | `crypto/rsa.py` |

Keys live under `keys/` (not inside the database). In production these would be in an HSM/KMS (as described in your technical report).

### b) Protocol level

| Protocol | Role in prototype |
|----------|-------------------|
| **HTTPS / TLS 1.2+** | All browser ↔ app traffic (self-signed cert in `certificates/`) |
| **Secure cookies** | `HttpOnly`, `SameSite=Lax`, `Secure` when HTTPS is on |
| **SMTP over TLS / SFTP** | Not wired into the UI; see “Production notes” below for how they fit the architecture |

### c) System level

| Control | Implementation |
|---------|----------------|
| **Authentication + RBAC** | Flask-Login; roles `user` / `admin` |
| **Audit logging** | `logs/audit.log` (login, transfer, balance, history) |
| **Session timeout** | 15 minutes idle |
| **Database backup** | `backup.py` with SHA-256 integrity check |
| **Firewall / IDS** | Documented below for the Rocky VM (not simulated inside Flask) |

#### Recommended Rocky Linux host hardening (demo / viva)

```bash
# Allow only HTTPS to the app port (example: 8443)
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --reload

# Optional: fail2ban for SSH brute-force protection
sudo dnf install -y fail2ban
sudo systemctl enable --now fail2ban
```

For IDS concepts, relate this prototype to your architecture diagram (IDS/IPS at zone boundaries, SIEM collecting logs). This app’s `audit.log` is the lightweight equivalent of application-level monitoring.

---

## Environment variables

| Variable | Default | Meaning |
|----------|---------|---------|
| `BANK_HTTPS` | `1` | `1` = TLS, `0` = HTTP |
| `BANK_HOST` | `0.0.0.0` | Bind address |
| `BANK_PORT` | `8443` | Listen port |
| `BANK_SECRET_KEY` | random | Flask session secret (set a fixed value for persistent sessions across restarts) |

Example:

```bash
export BANK_SECRET_KEY="change-me-for-demo"
export BANK_PORT=8443
python3 app.py
```

---

## Production notes (prototype vs full design)

This lab prototype intentionally simplifies the architecture from your technical report:

- Single process + SQLite instead of DMZ / app / data tiers
- Self-signed TLS instead of a CA-issued certificate
- File-based AES/RSA keys instead of HSM/KMS
- Application audit file instead of a full SIEM
- Firewall/IDS described at host level rather than enterprise appliances

Those production controls remain valid for Part 1; this folder demonstrates that the **same security goals** can be applied in working code.

---

## Resetting the demo

```bash
rm -f bank.db
rm -rf keys/* certificates/* logs/audit.log
# Keep backups/ if you want historical copies
python3 app.py   # recreates DB, keys, cert, demo users
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Browser says certificate is not trusted | Expected for self-signed cert — proceed anyway, or use `BANK_HTTPS=0` for local HTTP |
| `ModuleNotFoundError` | Activate `.venv` and re-run `pip install -r requirements.txt` |
| Port already in use | `BANK_PORT=8444 python3 app.py` |
| Permission denied on keys | Ensure you own the project folder; keys are created with mode `600` when possible |
| Transfer fails / invalid signature | Do not edit `keys/rsa_*.pem` after transactions exist; reset DB+keys together |

---

## Assignment checklist

- [x] Algorithm: bcrypt, AES-256, SHA-256, RSA digital signatures  
- [x] Protocol: HTTPS/TLS for web content transfer  
- [x] System: auth/RBAC, audit logs, session timeout, backup script  
- [x] Documented firewall/IDS alignment for Rocky Linux host  

---

*Secure Banking Prototype — educational use only.*
