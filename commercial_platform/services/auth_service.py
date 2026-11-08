#!/usr/bin/env python3
"""
NexoraAI V14.1 Commercial Platform — Authentication & RBAC Service (`auth_service.py`)
--------------------------------------------------------------------------------------
Implements:
  - PBKDF2-HMAC-SHA256 (`600,000` iterations) with unique 16-byte random salt per user.
  - Constant-time password & session comparison (`hmac.compare_digest`).
  - Brute-force protection (`5` failed attempts locks account for `900` seconds).
  - Server-side session lifecycle with CSRF token protection and expiration.
  - Strict Role-Based Access Control (`customer` vs `admin`).
"""
import hashlib
import hmac
import os
import re
import secrets
import time
import uuid
from commercial_platform.database.db_manager import DatabaseManager, utc_now


class SecurityError(Exception):
    pass


class AuthorizationError(Exception):
    pass


class AuthenticationService:
    PBKDF2_ITERATIONS = 600000
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_SECONDS = 900.0
    SESSION_TTL_SECONDS = 86400.0

    def __init__(self, db: DatabaseManager):
        self.db = db
        self._session_secret = os.environ.get("NEXORA_SESSION_HMAC_SECRET") or secrets.token_hex(32)

    def _hash_password(self, password: str, salt_hex: str, iterations: int = PBKDF2_ITERATIONS) -> str:
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            iterations,
        )
        return dk.hex()

    def validate_password_strength(self, password: str) -> None:
        if not isinstance(password, str) or len(password) < 12:
            raise ValueError("Password must be at least 12 characters long.")
        if not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) or not re.search(r"[0-9]", password):
            raise ValueError("Password must include uppercase, lowercase, and numeric characters.")

    def register_user(
        self,
        email: str,
        password: str,
        full_name: str,
        organization: str = "",
        role: str = "customer",
        ip_address: str = "127.0.0.1",
    ) -> dict:
        email_clean = (email or "").strip().lower()
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email_clean):
            raise ValueError("Invalid email address format.")
        self.validate_password_strength(password)
        if role not in ("customer", "admin"):
            raise ValueError("Invalid user role.")

        salt_hex = secrets.token_bytes(16).hex()
        pw_hash = self._hash_password(password, salt_hex, self.PBKDF2_ITERATIONS)
        user_id = f"usr_{uuid.uuid4().hex[:16]}"

        with self.db.connect() as conn:
            cur = conn.execute("SELECT user_id FROM users WHERE email = ?", (email_clean,))
            if cur.fetchone() is not None:
                raise ValueError("An account with this email already exists.")
            conn.execute(
                """
                INSERT INTO users (
                    user_id, email, full_name, organization, password_hash, password_salt,
                    pbkdf2_iterations, role, is_active, failed_login_attempts, locked_until_ts,
                    analytics_opt_in, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0, 0.0, 1, ?)
                """,
                (
                    user_id,
                    email_clean,
                    full_name.strip(),
                    organization.strip(),
                    pw_hash,
                    salt_hex,
                    self.PBKDF2_ITERATIONS,
                    role,
                    utc_now(),
                ),
            )
            conn.commit()

        self.db.log_audit_event(user_id, role, "USER_REGISTER", user_id, "SUCCESS", ip_address, f"Registered {email_clean} ({role})")
        return {"user_id": user_id, "email": email_clean, "full_name": full_name.strip(), "role": role}

    def authenticate(self, email: str, password: str, ip_address: str = "127.0.0.1") -> dict:
        email_clean = (email or "").strip().lower()
        now = time.time()
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE email = ?", (email_clean,)).fetchone()
            if row is None:
                self.db.log_audit_event(None, "anonymous", "USER_LOGIN", email_clean, "FAILURE_UNKNOWN_USER", ip_address, "Unknown email")
                raise SecurityError("Invalid email or password.")

            if not row["is_active"]:
                raise SecurityError("Account is disabled.")

            if float(row["locked_until_ts"]) > now:
                self.db.log_audit_event(row["user_id"], row["role"], "USER_LOGIN", row["user_id"], "BLOCKED_LOCKOUT", ip_address, "Account temporarily locked")
                raise SecurityError("Account is temporarily locked due to repeated failed login attempts.")

            cand_hash = self._hash_password(password or "", row["password_salt"], int(row["pbkdf2_iterations"]))
            if not hmac.compare_digest(cand_hash, row["password_hash"]):
                fails = int(row["failed_login_attempts"]) + 1
                lock_until = (now + self.LOCKOUT_SECONDS) if fails >= self.MAX_FAILED_ATTEMPTS else 0.0
                conn.execute(
                    "UPDATE users SET failed_login_attempts = ?, locked_until_ts = ? WHERE user_id = ?",
                    (fails, lock_until, row["user_id"]),
                )
                conn.commit()
                self.db.log_audit_event(row["user_id"], row["role"], "USER_LOGIN", row["user_id"], "FAILURE_BAD_PASSWORD", ip_address, f"Failed attempt #{fails}")
                raise SecurityError("Invalid email or password.")

            # Reset failed attempts on valid login
            conn.execute("UPDATE users SET failed_login_attempts = 0, locked_until_ts = 0.0 WHERE user_id = ?", (row["user_id"],))

            raw_token = secrets.token_urlsafe(32)
            csrf_token = secrets.token_hex(16)
            session_id = f"ses_{uuid.uuid4().hex[:16]}"
            sig = hmac.new(self._session_secret.encode("utf-8"), f"{session_id}:{raw_token}".encode("utf-8"), hashlib.sha256).hexdigest()
            signed_bearer = f"{session_id}.{raw_token}.{sig}"
            token_sha = hashlib.sha256(signed_bearer.encode("utf-8")).hexdigest()
            exp_ts = now + self.SESSION_TTL_SECONDS

            conn.execute(
                """
                INSERT INTO sessions (session_id, user_id, token_Fix_sha256, csrf_token, ip_address, expires_at_ts, revoked, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (session_id, row["user_id"], token_sha, csrf_token, ip_address, exp_ts, utc_now()),
            )
            conn.commit()

        self.db.log_audit_event(row["user_id"], row["role"], "USER_LOGIN", session_id, "SUCCESS", ip_address, "Issued signed session token")
        return {
            "session_id": session_id,
            "session_token": signed_bearer,
            "csrf_token": csrf_token,
            "user_id": row["user_id"],
            "email": row["email"],
            "full_name": row["full_name"],
            "role": row["role"],
            "expires_at_ts": exp_ts,
        }

    def verify_session(self, session_token: str, required_role: str | None = None, ip_address: str = "127.0.0.1") -> dict:
        if not session_token or session_token.count(".") != 2:
            raise SecurityError("Missing or malformed session token.")
        session_id, raw_tok, provided_sig = session_token.split(".")
        expected_sig = hmac.new(
            self._session_secret.encode("utf-8"),
            f"{session_id}:{raw_tok}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(provided_sig, expected_sig):
            self.db.log_audit_event(None, "anonymous", "SESSION_VERIFY", session_id, "FORGED_SIGNATURE", ip_address, "Session HMAC mismatch")
            raise SecurityError("Invalid session token signature.")

        token_sha = hashlib.sha256(session_token.encode("utf-8")).hexdigest()
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT s.*, u.email, u.full_name, u.organization, u.role, u.is_active
                FROM sessions s JOIN users u ON s.user_id = u.user_id
                WHERE s.session_id = ?
                """,
                (session_id,),
            ).fetchone()
            if row is None or row["revoked"] or not row["is_active"]:
                raise SecurityError("Session is invalid or revoked.")
            if not hmac.compare_digest(row["token_Fix_sha256"], token_sha):
                raise SecurityError("Session hash mismatch.")
            if float(row["expires_at_ts"]) < time.time():
                raise SecurityError("Session has expired.")

        if required_role and row["role"] != required_role:
            self.db.log_audit_event(
                row["user_id"],
                row["role"],
                "RBAC_VIOLATION",
                f"required={required_role}",
                "DENIED",
                ip_address,
                f"User with role '{row['role']}' attempted to access '{required_role}' endpoint.",
            )
            raise AuthorizationError(f"Access denied: '{required_role}' role required.")

        return {
            "user_id": row["user_id"],
            "email": row["email"],
            "full_name": row["full_name"],
            "organization": row["organization"],
            "role": row["role"],
            "session_id": row["session_id"],
            "csrf_token": row["csrf_token"],
        }

    def revoke_session(self, session_token: str, ip_address: str = "127.0.0.1") -> dict:
        if not session_token or session_token.count(".") != 2:
            raise SecurityError("Invalid session token format.")
        session_id = session_token.split(".")[0]
        with self.db.connect() as conn:
            cur = conn.execute("UPDATE sessions SET revoked = 1 WHERE session_id = ?", (session_id,))
            if cur.rowcount == 0:
                raise SecurityError("Session not found.")
            row = conn.execute("SELECT user_id FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
            uid = row["user_id"] if row else None
            conn.commit()
        self.db.log_audit_event(uid, "user", "USER_LOGOUT", session_id, "SUCCESS", ip_address, "Session successfully revoked")
        return {"revoked": True, "session_id": session_id}

    def update_profile(self, user_id: str, full_name: str, organization: str = "", ip_address: str = "127.0.0.1") -> dict:
        name_clean = full_name.strip()
        org_clean = organization.strip()
        if not name_clean:
            raise ValueError("Full name cannot be blank.")
        with self.db.connect() as conn:
            cur = conn.execute(
                "UPDATE users SET full_name = ?, organization = ? WHERE user_id = ?",
                (name_clean, org_clean, user_id),
            )
            if cur.rowcount == 0:
                raise SecurityError("User not found.")
            conn.commit()
            u = conn.execute("SELECT user_id, email, full_name, organization, role FROM users WHERE user_id = ?", (user_id,)).fetchone()
            d = dict(u)
        self.db.log_audit_event(user_id, d["role"], "PROFILE_UPDATE", user_id, "SUCCESS", ip_address, f"Updated profile for {d['email']}")
        return d

    def list_customers(self, limit: int = 100, offset: int = 0) -> list[dict]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT u.user_id, u.email, u.full_name, u.organization, u.role, u.is_active, u.created_at,
                       (SELECT COUNT(*) FROM licenses l WHERE l.user_id = u.user_id) AS license_count,
                       (SELECT COUNT(*) FROM device_activations d JOIN licenses l ON d.license_id = l.license_id WHERE l.user_id = u.user_id AND d.status = 'ACTIVE') AS active_devices_count
                FROM users u
                WHERE u.role = 'customer'
                ORDER BY u.created_at DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
            return [dict(r) for r in rows]

    def toggle_user_active(self, admin_user_id: str, target_user_id: str, is_active: bool, ip_address: str = "127.0.0.1") -> dict:
        if admin_user_id == target_user_id:
            raise ValueError("Administrators cannot deactivate their own administrative account.")
        with self.db.connect() as conn:
            cur = conn.execute(
                "UPDATE users SET is_active = ? WHERE user_id = ?",
                (1 if is_active else 0, target_user_id),
            )
            if cur.rowcount == 0:
                raise SecurityError(f"Target user not found: {target_user_id}")
            if not is_active:
                conn.execute("UPDATE sessions SET revoked = 1 WHERE user_id = ?", (target_user_id,))
            conn.commit()
            row = conn.execute("SELECT user_id, email, is_active, role FROM users WHERE user_id = ?", (target_user_id,)).fetchone()
            res = dict(row)
        self.db.log_audit_event(
            admin_user_id,
            "admin",
            "ADMIN_USER_STATUS_CHANGE",
            target_user_id,
            "SUCCESS",
            ip_address,
            f"Set is_active={is_active} for {res['email']}",
        )
        return res
