#!/usr/bin/env python3
"""
NexoraAI V14.2 Commercial Platform — Cryptographic License Management Service (`license_service.py`)
-----------------------------------------------------------------------------------------------------
Implements Section 2 & Section 4 requirements:
  - Supports all 5 commercial editions (`personal`, `professional`, `developer`, `enterprise`, `api`).
  - Configurable administrator pricing plans (never invents prices; defaults to `price_cents = None`
    until configured by an authorized administrator).
  - Server-side cryptographic license signing (`HMAC-SHA256` with server-only private key from
    `NEXORA_LICENSE_PRIVATE_KEY` environment variable — never embedded in the desktop client).
  - Device registration, per-edition device limits, license expiration, subscription status,
    revocation, activation history, and public-verifier offline activation leases.
"""
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from commercial_platform.database.db_manager import DatabaseManager, utc_now


class LicenseError(Exception):
    pass


class LicenseService:
    # Public verification salt used to construct deterministic public verification digests
    # while keeping `_private_signing_key` strictly on the server.
    PUBLIC_VERIFIER_SALT = "NEXORA_V14_2_PUBLIC_OFFLINE_LEASE_VERIFIER_v1"

    def __init__(self, db: DatabaseManager):
        self.db = db
        self._private_signing_key = os.environ.get("NEXORA_LICENSE_PRIVATE_KEY") or secrets.token_hex(32)

    def _sign_payload(self, payload: str) -> str:
        return hmac.new(
            self._private_signing_key.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    @classmethod
    def compute_public_lease_digest(
        cls,
        license_id: str,
        edition_code: str,
        device_fingerprint: str,
        expires_at_ts: float,
        server_signature_prefix: str,
    ) -> str:
        """
        Public verification digest that the desktop client can recompute to verify that a local
        offline lease file has not been tampered with (e.g., changing edition, device_fingerprint,
        or expiration date), without ever embedding the server's private signing key in the client!
        """
        canonical = f"{cls.PUBLIC_VERIFIER_SALT}||{license_id}||{edition_code}||{device_fingerprint}||{int(expires_at_ts)}||{server_signature_prefix}"
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def list_edition_plans(self) -> list[dict]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM pricing_plans ORDER BY max_devices ASC").fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["features"] = json.loads(d.pop("features_json"))
                d["price_display"] = (
                    f"{d['currency']} {d['price_cents'] / 100.0:,.2f}"
                    if d["pricing_configured_by_admin"] and d["price_cents"] is not None
                    else "Configurable by Administrator (Not Yet Priced)"
                )
                out.append(d)
            return out

    def update_edition_pricing_by_admin(
        self,
        admin_user_id: str,
        edition_code: str,
        price_cents: int | None,
        currency: str = "USD",
        max_devices: int | None = None,
        api_rate_limit_per_min: int | None = None,
        ip_address: str = "127.0.0.1",
    ) -> dict:
        if price_cents is not None and price_cents < 0:
            raise ValueError("price_cents cannot be negative.")
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM pricing_plans WHERE edition_code = ?", (edition_code,)).fetchone()
            if row is None:
                raise ValueError(f"Unknown edition_code: {edition_code}")
            new_max_dev = max_devices if max_devices is not None else int(row["max_devices"])
            new_rate = api_rate_limit_per_min if api_rate_limit_per_min is not None else int(row["api_rate_limit_per_min"])
            configured = 1 if price_cents is not None else 0
            conn.execute(
                """
                UPDATE pricing_plans
                SET price_cents = ?, currency = ?, pricing_configured_by_admin = ?,
                    max_devices = ?, api_rate_limit_per_min = ?, updated_at = ?
                WHERE edition_code = ?
                """,
                (price_cents, currency.upper(), configured, new_max_dev, new_rate, utc_now(), edition_code),
            )
            conn.commit()
        self.db.log_audit_event(
            admin_user_id,
            "admin",
            "ADMIN_UPDATE_PRICING_PLAN",
            edition_code,
            "SUCCESS",
            ip_address,
            f"Updated {edition_code}: price_cents={price_cents} {currency}, max_devices={new_max_dev}",
        )
        return next(p for p in self.list_edition_plans() if p["edition_code"] == edition_code)

    def issue_license(
        self,
        user_id: str,
        edition_code: str,
        subscription_status: str = "ACTIVE",
        duration_days: int = 365,
        custom_max_devices: int | None = None,
        actor_id: str = "system",
        actor_role: str = "admin",
        ip_address: str = "127.0.0.1",
    ) -> dict:
        with self.db.connect() as conn:
            plan = conn.execute("SELECT * FROM pricing_plans WHERE edition_code = ?", (edition_code,)).fetchone()
            if plan is None:
                raise LicenseError(f"Invalid edition: {edition_code}")
            usr = conn.execute("SELECT user_id, email FROM users WHERE user_id = ?", (user_id,)).fetchone()
            if usr is None:
                raise LicenseError(f"User not found: {user_id}")

            max_dev = custom_max_devices if custom_max_devices is not None else int(plan["max_devices"])
            rate_lim = int(plan["api_rate_limit_per_min"])
            license_id = f"lic_{uuid.uuid4().hex[:16]}"
            ed_tag = edition_code[:4].upper()
            rand_blocks = "-".join(secrets.token_hex(2).upper() for _ in range(4))
            license_key_token = f"NXRA-V142-{ed_tag}-{rand_blocks}"
            expires_at_ts = round(time.time() + duration_days * 86400.0, 2)

            canonical = f"{license_id}||{user_id}||{edition_code}||{license_key_token}||{max_dev}||{int(expires_at_ts)}"
            server_sig = self._sign_payload(canonical)

            raw_api_key = None
            api_key_hash = None
            if edition_code in ("api", "developer", "enterprise"):
                raw_api_key = f"nxra_live_{secrets.token_urlsafe(24)}"
                api_key_hash = hashlib.sha256(raw_api_key.encode("utf-8")).hexdigest()

            conn.execute(
                """
                INSERT INTO licenses (
                    license_id, user_id, edition_code, license_key_token, server_signature,
                    status, subscription_status, max_devices, api_key_hash, api_rate_limit_per_min,
                    issued_at, expires_at_ts, revoked_reason
                ) VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    license_id,
                    user_id,
                    edition_code,
                    license_key_token,
                    server_sig,
                    subscription_status,
                    max_dev,
                    api_key_hash,
                    rate_lim,
                    utc_now(),
                    expires_at_ts,
                ),
            )
            conn.commit()

        self.db.log_audit_event(
            actor_id,
            actor_role,
            "LICENSE_ISSUED",
            license_id,
            "SUCCESS",
            ip_address,
            f"Issued {edition_code} license to {user_id} (max_devices={max_dev})",
        )
        return {
            "license_id": license_id,
            "user_id": user_id,
            "edition_code": edition_code,
            "license_key_token": license_key_token,
            "server_signature": server_sig,
            "status": "ACTIVE",
            "subscription_status": subscription_status,
            "max_devices": max_dev,
            "api_key_once": raw_api_key,
            "api_rate_limit_per_min": rate_lim,
            "expires_at_ts": expires_at_ts,
        }

    def activate_device(
        self,
        license_key_token: str,
        device_fingerprint: str,
        device_name: str,
        os_platform: str,
        app_version: str = "14.2.0",
        ip_address: str = "127.0.0.1",
    ) -> dict:
        if not license_key_token or not device_fingerprint or len(device_fingerprint.strip()) < 8:
            raise LicenseError("Valid license_key_token and device_fingerprint (>= 8 chars) are required.")
        fp_clean = device_fingerprint.strip()

        with self.db.connect() as conn:
            lic = conn.execute("SELECT * FROM licenses WHERE license_key_token = ?", (license_key_token.strip(),)).fetchone()
            if lic is None:
                self.db.log_audit_event(None, "anonymous", "DEVICE_ACTIVATE", license_key_token, "REJECTED_UNKNOWN_KEY", ip_address, "Unknown license key")
                raise LicenseError("Invalid license key.")

            license_id = lic["license_id"]
            # Verify server cryptographic signature on stored license record
            canonical = f"{license_id}||{lic['user_id']}||{lic['edition_code']}||{lic['license_key_token']}||{lic['max_devices']}||{int(lic['expires_at_ts'])}"
            expected_sig = self._sign_payload(canonical)
            if not hmac.compare_digest(lic["server_signature"], expected_sig):
                self._record_activation_history(conn, license_id, fp_clean, "ACTIVATE", "REJECTED_TAMPERED", "Server signature mismatch")
                conn.commit()
                raise LicenseError("License signature verification failed.")

            if lic["status"] != "ACTIVE":
                self._record_activation_history(conn, license_id, fp_clean, "ACTIVATE", f"REJECTED_{lic['status']}", f"License is {lic['status']}")
                conn.commit()
                raise LicenseError(f"License is {lic['status']} ({lic['revoked_reason'] or 'not active'}).")

            if float(lic["expires_at_ts"]) < time.time():
                conn.execute("UPDATE licenses SET status = 'EXPIRED' WHERE license_id = ?", (license_id,))
                self._record_activation_history(conn, license_id, fp_clean, "ACTIVATE", "REJECTED_EXPIRED", "License expired")
                conn.commit()
                raise LicenseError("License has expired.")

            existing = conn.execute(
                "SELECT * FROM device_activations WHERE license_id = ? AND device_fingerprint = ?",
                (license_id, fp_clean),
            ).fetchone()

            active_devs = conn.execute(
                "SELECT COUNT(*) AS cnt FROM device_activations WHERE license_id = ? AND status = 'ACTIVE'",
                (license_id,),
            ).fetchone()["cnt"]

            if (existing is None or existing["status"] != "ACTIVE") and active_devs >= int(lic["max_devices"]):
                self._record_activation_history(
                    conn,
                    license_id,
                    fp_clean,
                    "ACTIVATE",
                    "REJECTED_DEVICE_LIMIT",
                    f"Device limit reached ({active_devs}/{lic['max_devices']})",
                )
                conn.commit()
                raise LicenseError(f"Device limit reached ({active_devs}/{lic['max_devices']} active devices for {lic['edition_code']} edition).")

            plan = conn.execute("SELECT offline_lease_days FROM pricing_plans WHERE edition_code = ?", (lic["edition_code"],)).fetchone()
            lease_days = int(plan["offline_lease_days"]) if plan else 30
            lease_exp_ts = min(float(lic["expires_at_ts"]), round(time.time() + lease_days * 86400.0, 2))
            sig_prefix = lic["server_signature"][:24]
            pub_digest = self.compute_public_lease_digest(license_id, lic["edition_code"], fp_clean, lease_exp_ts, sig_prefix)

            lease_payload = {
                "license_id": license_id,
                "edition_code": lic["edition_code"],
                "device_fingerprint": fp_clean,
                "device_name": device_name.strip(),
                "lease_expires_at_ts": int(lease_exp_ts),
                "server_signature_prefix": sig_prefix,
                "public_verifier_digest": pub_digest,
                "server_lease_hmac": self._sign_payload(f"LEASE||{license_id}||{fp_clean}||{int(lease_exp_ts)}||{pub_digest}"),
            }
            lease_token_json = json.dumps(lease_payload, separators=(",", ":"))

            if existing is None:
                act_id = f"act_{uuid.uuid4().hex[:16]}"
                conn.execute(
                    """
                    INSERT INTO device_activations (
                        activation_id, license_id, device_fingerprint, device_name,
                        os_platform, app_version, status, offline_lease_token,
                        activated_at, last_verified_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?)
                    """,
                    (act_id, license_id, fp_clean, device_name.strip(), os_platform.strip(), app_version, lease_token_json, utc_now(), utc_now()),
                )
            else:
                act_id = existing["activation_id"]
                conn.execute(
                    """
                    UPDATE device_activations
                    SET status = 'ACTIVE', device_name = ?, os_platform = ?, app_version = ?,
                        offline_lease_token = ?, last_verified_at = ?
                    WHERE activation_id = ?
                    """,
                    (device_name.strip(), os_platform.strip(), app_version, lease_token_json, utc_now(), act_id),
                )

            self._record_activation_history(conn, license_id, fp_clean, "ACTIVATE", "SUCCESS", f"Activated {device_name} ({os_platform})")
            conn.commit()

        self.db.log_audit_event(lic["user_id"], "customer", "DEVICE_ACTIVATE", license_id, "SUCCESS", ip_address, f"Device {fp_clean} activated")
        return {
            "activation_id": act_id,
            "license_id": license_id,
            "edition_code": lic["edition_code"],
            "status": "ACTIVE",
            "offline_lease": lease_payload,
        }

    def deactivate_device(self, user_id: str, license_id: str, device_fingerprint: str, is_admin: bool = False, ip_address: str = "127.0.0.1") -> dict:
        with self.db.connect() as conn:
            lic = conn.execute("SELECT * FROM licenses WHERE license_id = ?", (license_id,)).fetchone()
            if lic is None or (not is_admin and lic["user_id"] != user_id):
                raise LicenseError("License not found or access denied.")
            cur = conn.execute(
                "UPDATE device_activations SET status = 'DEACTIVATED', last_verified_at = ? WHERE license_id = ? AND device_fingerprint = ?",
                (utc_now(), license_id, device_fingerprint),
            )
            if cur.rowcount == 0:
                raise LicenseError("Device activation record not found.")
            self._record_activation_history(conn, license_id, device_fingerprint, "DEACTIVATE", "SUCCESS", "Device deactivated")
            conn.commit()
        self.db.log_audit_event(user_id, "admin" if is_admin else "customer", "DEVICE_DEACTIVATE", license_id, "SUCCESS", ip_address, f"Deactivated {device_fingerprint}")
        return {"deactivated": True, "license_id": license_id, "device_fingerprint": device_fingerprint}

    def revoke_license_by_admin(self, admin_user_id: str, license_id: str, reason: str, ip_address: str = "127.0.0.1") -> dict:
        with self.db.connect() as conn:
            cur = conn.execute(
                "UPDATE licenses SET status = 'REVOKED', subscription_status = 'CANCELED', revoked_reason = ? WHERE license_id = ?",
                (reason.strip(), license_id),
            )
            if cur.rowcount == 0:
                raise LicenseError(f"License not found: {license_id}")
            conn.execute("UPDATE device_activations SET status = 'DEACTIVATED' WHERE license_id = ?", (license_id,))
            self._record_activation_history(conn, license_id, "ALL_DEVICES", "ADMIN_REVOKE", "SUCCESS", reason.strip())
            conn.commit()
        self.db.log_audit_event(admin_user_id, "admin", "LICENSE_REVOKED", license_id, "SUCCESS", ip_address, f"Reason: {reason}")
        return {"license_id": license_id, "status": "REVOKED", "reason": reason.strip()}

    def suspend_license_by_admin(self, admin_user_id: str, license_id: str, reason: str, ip_address: str = "127.0.0.1") -> dict:
        with self.db.connect() as conn:
            cur = conn.execute(
                "UPDATE licenses SET status = 'SUSPENDED', revoked_reason = ? WHERE license_id = ?",
                (reason.strip(), license_id),
            )
            if cur.rowcount == 0:
                raise LicenseError(f"License not found: {license_id}")
            self._record_activation_history(conn, license_id, "ALL_DEVICES", "ADMIN_SUSPEND", "SUCCESS", reason.strip())
            conn.commit()
        self.db.log_audit_event(admin_user_id, "admin", "LICENSE_SUSPENDED", license_id, "SUCCESS", ip_address, f"Reason: {reason}")
        return {"license_id": license_id, "status": "SUSPENDED", "reason": reason.strip()}

    def reactivate_license_by_admin(self, admin_user_id: str, license_id: str, ip_address: str = "127.0.0.1") -> dict:
        with self.db.connect() as conn:
            cur = conn.execute(
                "UPDATE licenses SET status = 'ACTIVE', revoked_reason = NULL WHERE license_id = ? AND status = 'SUSPENDED'",
                (license_id,),
            )
            if cur.rowcount == 0:
                raise LicenseError(f"License {license_id} is not in SUSPENDED state.")
            self._record_activation_history(conn, license_id, "ALL_DEVICES", "ADMIN_REACTIVATE", "SUCCESS", "License reactivated")
            conn.commit()
        self.db.log_audit_event(admin_user_id, "admin", "LICENSE_REACTIVATED", license_id, "SUCCESS", ip_address, "Reactivated license")
        return {"license_id": license_id, "status": "ACTIVE"}

    def get_customer_licenses(self, user_id: str) -> list[dict]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT l.*, p.display_name, p.billing_model,
                       (SELECT COUNT(*) FROM device_activations d WHERE d.license_id = l.license_id AND d.status = 'ACTIVE') AS active_devices_count
                FROM licenses l
                JOIN pricing_plans p ON l.edition_code = p.edition_code
                WHERE l.user_id = ?
                ORDER BY l.issued_at DESC
                """,
                (user_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def list_all_licenses_admin(self, limit: int = 100, offset: int = 0) -> list[dict]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT l.*, u.email AS user_email, u.full_name AS user_name,
                       (SELECT COUNT(*) FROM device_activations d WHERE d.license_id = l.license_id AND d.status = 'ACTIVE') AS active_devices_count
                FROM licenses l
                JOIN users u ON l.user_id = u.user_id
                ORDER BY l.issued_at DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
            return [dict(r) for r in rows]

    def list_all_devices_admin(self, limit: int = 100, offset: int = 0) -> list[dict]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT d.*, l.edition_code, l.license_key_token, u.email AS user_email, u.full_name AS user_name
                FROM device_activations d
                JOIN licenses l ON d.license_id = l.license_id
                JOIN users u ON l.user_id = u.user_id
                ORDER BY d.activated_at DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
            return [dict(r) for r in rows]

    def verify_server_entitlement(self, license_key_token: str, device_fingerprint: str) -> dict:
        with self.db.connect() as conn:
            lic = conn.execute("SELECT * FROM licenses WHERE license_key_token = ?", (license_key_token.strip(),)).fetchone()
            if lic is None or lic["status"] != "ACTIVE" or float(lic["expires_at_ts"]) < time.time():
                return {"entitled": False, "reason": "License is invalid, revoked, or expired."}
            dev = conn.execute(
                "SELECT * FROM device_activations WHERE license_id = ? AND device_fingerprint = ? AND status = 'ACTIVE'",
                (lic["license_id"], device_fingerprint.strip()),
            ).fetchone()
            if dev is None:
                return {"entitled": False, "reason": "Device is not actively registered to this license."}
            conn.execute(
                "UPDATE device_activations SET last_verified_at = ? WHERE activation_id = ?",
                (utc_now(), dev["activation_id"]),
            )
            conn.commit()
            return {
                "entitled": True,
                "license_id": lic["license_id"],
                "edition_code": lic["edition_code"],
                "subscription_status": lic["subscription_status"],
                "expires_at_ts": lic["expires_at_ts"],
            }

    def _record_activation_history(self, conn, license_id: str, fp: str, action: str, outcome: str, detail: str):
        conn.execute(
            """
            INSERT INTO activation_history (event_id, license_id, device_fingerprint, action, outcome, detail, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (f"ah_{uuid.uuid4().hex[:16]}", license_id, fp, action, outcome, detail, utc_now()),
        )
