"""
Secure Banking System Prototype
Algorithm / protocol / system-level security demo for assignment Part 2.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)

from crypto.aes import decrypt_aes, encrypt_aes, ensure_aes_key
from crypto.hashing import hash_password, sha256_hex, verify_password
from crypto.rsa import ensure_rsa_keys, sign_data, verify_signature

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "bank.db"
LOG_PATH = BASE_DIR / "logs" / "audit.log"
CERT_DIR = BASE_DIR / "certificates"
SESSION_TIMEOUT_MINUTES = 15

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get(
    "BANK_SECRET_KEY", secrets.token_hex(32)
)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=SESSION_TIMEOUT_MINUTES)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Secure cookies when running under HTTPS
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("BANK_HTTPS", "1") == "1"

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "warning"


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    ensure_aes_key()
    ensure_rsa_keys()
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('user', 'admin'))
        );

        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            balance REAL NOT NULL DEFAULT 0,
            encrypted_account_number TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            payload_hash TEXT NOT NULL,
            signature TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (sender_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
        );
        """
    )

    # Seed demo users only if empty
    row = db.execute("SELECT COUNT(*) AS c FROM users").fetchone()
    if row[0] == 0:
        demo_users = [
            ("alice", "Alice@123", "user", 5000.00, "ACC-1001-ALICE"),
            ("bob", "Bob@12345", "user", 2500.00, "ACC-1002-BOB"),
            ("admin", "Admin@123", "admin", 10000.00, "ACC-0001-ADMIN"),
        ]
        for username, password, role, balance, account_no in demo_users:
            cur = db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, hash_password(password), role),
            )
            user_id = cur.lastrowid
            db.execute(
                """
                INSERT INTO accounts (user_id, balance, encrypted_account_number)
                VALUES (?, ?, ?)
                """,
                (user_id, balance, encrypt_aes(account_no)),
            )
        db.commit()
        audit("SYSTEM", "Database initialized with demo users")
    db.close()


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

def audit(actor: str, message: str) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    line = f"[{ts}] actor={actor} | {message}\n"
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(line)


# ---------------------------------------------------------------------------
# Auth / session
# ---------------------------------------------------------------------------

class User(UserMixin):
    def __init__(self, row: sqlite3.Row):
        self.id = row["id"]
        self.username = row["username"]
        self.role = row["role"]
        self.password_hash = row["password_hash"]

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


@login_manager.user_loader
def load_user(user_id: str):
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return User(row) if row else None


@app.before_request
def enforce_session_timeout():
    if not current_user.is_authenticated:
        return None
    last = session.get("last_activity")
    now = datetime.now(timezone.utc).timestamp()
    if last and (now - last) > SESSION_TIMEOUT_MINUTES * 60:
        logout_user()
        session.clear()
        flash("Session expired due to inactivity. Please log in again.", "warning")
        return redirect(url_for("login"))
    session["last_activity"] = now
    session.permanent = True
    return None


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Admin access required.", "danger")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)

    return wrapped


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_account(user_id: int):
    return (
        get_db()
        .execute("SELECT * FROM accounts WHERE user_id = ?", (user_id,))
        .fetchone()
    )


def masked_account_number(encrypted: str) -> str:
    try:
        plain = decrypt_aes(encrypted)
        if len(plain) <= 4:
            return "****"
        return ("*" * (len(plain) - 4)) + plain[-4:]
    except Exception:
        return "********"


def build_tx_payload(sender_id: int, receiver_id: int, amount: float, ts: str) -> str:
    return f"{sender_id}|{receiver_id}|{amount:.2f}|{ts}"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        db = get_db()
        row = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if row and verify_password(password, row["password_hash"]):
            user = User(row)
            login_user(user)
            session["last_activity"] = datetime.now(timezone.utc).timestamp()
            session.permanent = True
            audit(username, "LOGIN_SUCCESS")
            flash(f"Welcome, {username}.", "success")
            return redirect(url_for("dashboard"))

        audit(username or "unknown", "LOGIN_FAILED")
        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    audit(current_user.username, "LOGOUT")
    logout_user()
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    account = get_account(current_user.id)
    account_display = masked_account_number(account["encrypted_account_number"])
    return render_template(
        "dashboard.html",
        balance=account["balance"],
        account_display=account_display,
        role=current_user.role,
    )


@app.route("/balance")
@login_required
def balance():
    account = get_account(current_user.id)
    plain_account = decrypt_aes(account["encrypted_account_number"])
    audit(current_user.username, "VIEW_BALANCE")
    return render_template(
        "balance.html",
        balance=account["balance"],
        account_number=plain_account,
    )


@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    db = get_db()
    users = db.execute(
        "SELECT id, username FROM users WHERE id != ? ORDER BY username",
        (current_user.id,),
    ).fetchall()

    if request.method == "POST":
        try:
            receiver_id = int(request.form.get("receiver_id", "0"))
            amount = float(request.form.get("amount", "0"))
        except ValueError:
            flash("Invalid transfer details.", "danger")
            return redirect(url_for("transfer"))

        if amount <= 0:
            flash("Amount must be greater than zero.", "danger")
            return redirect(url_for("transfer"))

        receiver = db.execute(
            "SELECT * FROM users WHERE id = ?", (receiver_id,)
        ).fetchone()
        if not receiver:
            flash("Receiver not found.", "danger")
            return redirect(url_for("transfer"))

        sender_account = get_account(current_user.id)
        receiver_account = get_account(receiver_id)

        if sender_account["balance"] < amount:
            audit(
                current_user.username,
                f"TRANSFER_FAILED insufficient_funds amount={amount:.2f} to={receiver['username']}",
            )
            flash("Insufficient balance.", "danger")
            return redirect(url_for("transfer"))

        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        payload = build_tx_payload(current_user.id, receiver_id, amount, ts)
        payload_hash = sha256_hex(payload)
        signature = sign_data(payload)

        # Integrity check before commit
        if not verify_signature(payload, signature):
            audit(current_user.username, "TRANSFER_FAILED signature_invalid")
            flash("Transaction signature verification failed.", "danger")
            return redirect(url_for("transfer"))

        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "UPDATE accounts SET balance = balance - ? WHERE user_id = ?",
                (amount, current_user.id),
            )
            db.execute(
                "UPDATE accounts SET balance = balance + ? WHERE user_id = ?",
                (amount, receiver_id),
            )
            db.execute(
                """
                INSERT INTO transactions
                (sender_id, receiver_id, amount, payload_hash, signature, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    current_user.id,
                    receiver_id,
                    amount,
                    payload_hash,
                    signature,
                    ts,
                ),
            )
            db.commit()
        except Exception as exc:
            db.rollback()
            audit(current_user.username, f"TRANSFER_FAILED error={exc}")
            flash("Transfer failed. Please try again.", "danger")
            return redirect(url_for("transfer"))

        audit(
            current_user.username,
            f"TRANSFER_SUCCESS amount={amount:.2f} to={receiver['username']} hash={payload_hash[:16]}...",
        )
        flash(
            f"Transferred ${amount:.2f} to {receiver['username']}. "
            "Transaction digitally signed.",
            "success",
        )
        return redirect(url_for("history"))

    return render_template("transfer.html", users=users)


@app.route("/history")
@login_required
def history():
    db = get_db()
    if current_user.is_admin:
        rows = db.execute(
            """
            SELECT t.*, s.username AS sender_name, r.username AS receiver_name
            FROM transactions t
            JOIN users s ON s.id = t.sender_id
            JOIN users r ON r.id = t.receiver_id
            ORDER BY t.id DESC
            """
        ).fetchall()
    else:
        rows = db.execute(
            """
            SELECT t.*, s.username AS sender_name, r.username AS receiver_name
            FROM transactions t
            JOIN users s ON s.id = t.sender_id
            JOIN users r ON r.id = t.receiver_id
            WHERE t.sender_id = ? OR t.receiver_id = ?
            ORDER BY t.id DESC
            """,
            (current_user.id, current_user.id),
        ).fetchall()

    verified = []
    for row in rows:
        payload = build_tx_payload(
            row["sender_id"], row["receiver_id"], row["amount"], row["timestamp"]
        )
        ok = (
            sha256_hex(payload) == row["payload_hash"]
            and verify_signature(payload, row["signature"])
        )
        verified.append({**dict(row), "signature_valid": ok})

    audit(current_user.username, "VIEW_HISTORY")
    return render_template("history.html", transactions=verified)


@app.route("/admin/logs")
@login_required
@admin_required
def admin_logs():
    lines = []
    if LOG_PATH.exists():
        lines = LOG_PATH.read_text(encoding="utf-8").splitlines()[-200:]
        lines.reverse()
    audit(current_user.username, "VIEW_AUDIT_LOGS")
    return render_template("admin_logs.html", lines=lines)


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

init_db()


def create_ssl_context():
    """Return (cert, key) paths for HTTPS, generating a self-signed cert if needed."""
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    cert_file = CERT_DIR / "server.crt"
    key_file = CERT_DIR / "server.key"

    if not cert_file.exists() or not key_file.exists():
        from OpenSSL import crypto

        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        cert = crypto.X509()
        cert.get_subject().CN = "secure-bank.local"
        cert.get_subject().O = "Secure Banking Prototype"
        cert.get_subject().C = "LK"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, "sha256")

        key_file.write_bytes(
            crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
        )
        cert_file.write_bytes(
            crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        )
        try:
            os.chmod(key_file, 0o600)
        except OSError:
            pass

    return str(cert_file), str(key_file)


if __name__ == "__main__":
    use_https = os.environ.get("BANK_HTTPS", "1") == "1"
    host = os.environ.get("BANK_HOST", "0.0.0.0")
    port = int(os.environ.get("BANK_PORT", "8443"))

    print("=" * 60)
    print(" Secure Banking Prototype")
    print("=" * 60)
    if use_https:
        ssl_ctx = create_ssl_context()
        print(f" HTTPS: https://127.0.0.1:{port}")
        print(" (Self-signed cert — browser will warn; proceed anyway)")
        app.run(host=host, port=port, ssl_context=ssl_ctx, debug=False)
    else:
        print(f" HTTP:  http://127.0.0.1:{port}")
        app.run(host=host, port=port, debug=False)
