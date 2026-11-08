#!/usr/bin/env python3
"""
NexoraAI V14.2 Commercial Platform — Controlled Distribution & Update Service (`distribution_service.py`)
---------------------------------------------------------------------------------------------------------
Implements Section 5 requirements:
  - Authenticated, time-limited, single-use signed download tokens (`download_tokens`).
  - Versioned releases with SHA-256 checksums and package signatures.
  - Strict commercial quarantine of the Qwen-compatible LoRA adapter (`commercial_distribution_allowed = 0`),
    preventing commercial download of the Qwen adapter until base-model/dataset IP obligations are cleared.
  - Realistic documentation of local weight extraction limitations.
  - Update check & rollback manifest support without overwriting original V14.1/V14.2 checkpoints.
"""
import datetime
import hashlib
import hmac
import os
import secrets
import time
import urllib.parse
import uuid
from commercial_platform.database.db_manager import DatabaseManager, utc_now


class DistributionError(Exception):
    pass


class ObjectStorageProvider:
    """
    Zero-dependency AWS S3 / Cloudflare R2 / Backblaze B2 / MinIO compatible SigV4 presigned URL provider.
    Ensures private storage credentials never leak to clients.
    """
    def __init__(self):
        self.backend = os.environ.get("NEXORA_STORAGE_BACKEND", "local").lower()
        self.endpoint_url = os.environ.get("NEXORA_S3_ENDPOINT_URL", "").rstrip("/")
        self.bucket = os.environ.get("NEXORA_S3_BUCKET", "")
        self.region = os.environ.get("NEXORA_S3_REGION", "auto")
        self.access_key_id = os.environ.get("NEXORA_S3_ACCESS_KEY_ID", "")
        self.secret_access_key = os.environ.get("NEXORA_S3_SECRET_ACCESS_KEY", "")

    @property
    def is_configured(self) -> bool:
        return bool(
            self.backend in ("s3", "r2", "b2", "minio")
            and self.bucket
            and self.access_key_id
            and self.secret_access_key
        )

    def generate_presigned_get_url(self, object_key: str, expires_in_sec: int = 900) -> str:
        if not self.is_configured:
            return ""
        key_clean = object_key.lstrip("/")
        now = datetime.datetime.now(datetime.timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        datestamp = now.strftime("%Y%m%d")

        parsed = urllib.parse.urlparse(self.endpoint_url) if self.endpoint_url else urllib.parse.urlparse(f"https://{self.bucket}.s3.{self.region}.amazonaws.com")
        host = parsed.netloc

        if self.endpoint_url:
            canonical_uri = f"/{self.bucket}/{urllib.parse.quote(key_clean, safe='-_.~/')}"
        else:
            canonical_uri = f"/{urllib.parse.quote(key_clean, safe='-_.~/')}"

        credential_scope = f"{datestamp}/{self.region}/s3/aws4_request"
        canonical_querystring = (
            f"X-Amz-Algorithm=AWS4-HMAC-SHA256"
            f"&X-Amz-Credential={urllib.parse.quote(f'{self.access_key_id}/{credential_scope}', safe='')}"
            f"&X-Amz-Date={amz_date}"
            f"&X-Amz-Expires={int(expires_in_sec)}"
            f"&X-Amz-SignedHeaders=host"
        )

        canonical_headers = f"host:{host}\n"
        signed_headers = "host"
        payload_hash = "UNSIGNED-PAYLOAD"

        canonical_request = (
            f"GET\n{canonical_uri}\n{canonical_querystring}\n"
            f"{canonical_headers}\n{signed_headers}\n{payload_hash}"
        )

        string_to_sign = (
            f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
            f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
        )

        def _sign(key: bytes, msg: str) -> bytes:
            return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

        k_date = _sign(f"AWS4{self.secret_access_key}".encode("utf-8"), datestamp)
        k_region = _sign(k_date, self.region)
        k_service = _sign(k_region, "s3")
        k_signing = _sign(k_service, "aws4_request")

        signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        base_endpoint = self.endpoint_url or f"https://{self.bucket}.s3.{self.region}.amazonaws.com"
        return f"{base_endpoint}{canonical_uri}?{canonical_querystring}&X-Amz-Signature={signature}"


class DistributionService:
    DOWNLOAD_TOKEN_TTL_SECONDS = 900.0  # 15-minute signed download URL lifetime

    def __init__(self, db: DatabaseManager):
        self.db = db
        self._dl_secret = os.environ.get("NEXORA_DOWNLOAD_HMAC_SECRET") or secrets.token_hex(32)
        self.storage_provider = ObjectStorageProvider()

    def list_releases(self, include_quarantined_for_admin: bool = False) -> list[dict]:
        with self.db.connect() as conn:
            if include_quarantined_for_admin:
                rows = conn.execute("SELECT * FROM product_releases ORDER BY published_at DESC").fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM product_releases WHERE commercial_distribution_allowed = 1 ORDER BY published_at DESC"
                ).fetchall()
            return [dict(r) for r in rows]

    def authorize_download(
        self,
        user_id: str,
        license_id: str,
        release_id: str,
        ip_address: str = "127.0.0.1",
    ) -> dict:
        with self.db.connect() as conn:
            lic = conn.execute(
                "SELECT * FROM licenses WHERE license_id = ? AND user_id = ?",
                (license_id, user_id),
            ).fetchone()
            if lic is None or lic["status"] != "ACTIVE" or float(lic["expires_at_ts"]) < time.time():
                self.db.log_audit_event(user_id, "customer", "DOWNLOAD_AUTH", release_id, "DENIED_INVALID_LICENSE", ip_address, f"License {license_id} not active")
                raise DistributionError("Active, non-expired license required to authorize software or model download.")

            rel = conn.execute("SELECT * FROM product_releases WHERE release_id = ?", (release_id,)).fetchone()
            if rel is None:
                raise DistributionError(f"Release not found: {release_id}")

            if int(rel["commercial_distribution_allowed"]) != 1 or rel["channel"] == "QUARANTINED_INTERNAL":
                self.db.log_audit_event(
                    user_id,
                    "customer",
                    "DOWNLOAD_AUTH_QUARANTINED",
                    release_id,
                    "BLOCKED_IP_QUARANTINE",
                    ip_address,
                    "Attempted to download IP-quarantined Qwen LoRA adapter.",
                )
                raise DistributionError(
                    "Commercial download blocked: This component (Qwen-compatible LoRA adapter) is quarantined "
                    "pending verification of base-model and dataset licensing obligations. Only the Native NexoraAI "
                    "standalone model is authorized for commercial distribution."
                )

            token_id = f"dlt_{uuid.uuid4().hex[:16]}"
            exp_ts = round(time.time() + self.DOWNLOAD_TOKEN_TTL_SECONDS, 2)
            payload = f"{token_id}||{user_id}||{license_id}||{release_id}||{int(exp_ts)}"
            sig = hmac.new(self._dl_secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
            signed_token = f"{token_id}.{int(exp_ts)}.{sig}"

            conn.execute(
                """
                INSERT INTO download_tokens (
                    token_id, user_id, license_id, release_id, token_signature,
                    expires_at_ts, used_count, max_uses, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 0, 1, ?)
                """,
                (token_id, user_id, license_id, release_id, sig, exp_ts, utc_now()),
            )
            conn.commit()

        self.db.log_audit_event(user_id, "customer", "DOWNLOAD_AUTH", release_id, "SUCCESS", ip_address, f"Issued token {token_id}")
        return {
            "download_token": signed_token,
            "release_id": release_id,
            "version": rel["version"],
            "artifact_path": rel["artifact_path"],
            "sha256_checksum": rel["sha256_checksum"],
            "size_bytes": rel["size_bytes"],
            "package_signature": rel["package_signature"],
            "expires_at_ts": exp_ts,
            "storage_backend": self.storage_provider.backend,
            "is_object_storage": self.storage_provider.is_configured,
            "weight_protection_disclosure": (
                "REALISTIC WEIGHT PROTECTION LIMITATION: Because local inference executes on the customer's CPU/RAM, "
                "determined local adversaries with root/debugger access can inspect in-memory tensors. NexoraAI mitigates "
                "unauthorized redistribution via authenticated download tokens, SHA-256 package signatures, per-device "
                "activation leases, and legal EULA enforcement rather than claiming unbreakable local DRM."
            ),
        }

    def consume_download_token(self, signed_token: str, ip_address: str = "127.0.0.1") -> dict:
        if not signed_token or signed_token.count(".") != 2:
            raise DistributionError("Invalid download token format.")
        token_id, exp_str, provided_sig = signed_token.split(".")
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM download_tokens WHERE token_id = ?", (token_id,)).fetchone()
            if row is None:
                raise DistributionError("Download token not found.")
            if int(row["used_count"]) >= int(row["max_uses"]):
                raise DistributionError("Download token has already been used.")
            if float(row["expires_at_ts"]) < time.time():
                raise DistributionError("Download token has expired.")

            payload = f"{token_id}||{row['user_id']}||{row['license_id']}||{row['release_id']}||{int(row['expires_at_ts'])}"
            expected_sig = hmac.new(self._dl_secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(provided_sig, expected_sig):
                raise DistributionError("Download token signature verification failed.")

            rel = conn.execute("SELECT * FROM product_releases WHERE release_id = ?", (row["release_id"],)).fetchone()
            if rel is None or int(rel["commercial_distribution_allowed"]) != 1:
                raise DistributionError("Release is not permitted for commercial distribution.")

            conn.execute("UPDATE download_tokens SET used_count = used_count + 1 WHERE token_id = ?", (token_id,))
            conn.commit()

        # Generate direct presigned URL if Cloudflare R2 / S3 is enabled
        presigned_url = None
        if self.storage_provider.is_configured:
            presigned_url = self.storage_provider.generate_presigned_get_url(rel["artifact_path"], expires_in_sec=900)

        self.db.log_audit_event(row["user_id"], "customer", "DOWNLOAD_CONSUMED", row["release_id"], "SUCCESS", ip_address, f"Token {token_id} consumed")
        return {
            "status": "AUTHORIZED_STREAM_READY",
            "release_id": rel["release_id"],
            "version": rel["version"],
            "artifact_path": rel["artifact_path"],
            "sha256_checksum": rel["sha256_checksum"],
            "package_signature": rel["package_signature"],
            "storage_backend": self.storage_provider.backend,
            "presigned_download_url": presigned_url,
            "direct_download_url": presigned_url or f"/api/v1/downloads/stream?token={signed_token}",
        }

    def check_for_updates(self, current_version: str = "14.1.0") -> dict:
        with self.db.connect() as conn:
            latest = conn.execute(
                "SELECT * FROM product_releases WHERE channel = 'STABLE' AND commercial_distribution_allowed = 1 ORDER BY published_at DESC LIMIT 1"
            ).fetchone()
            rollback = conn.execute(
                "SELECT * FROM product_releases WHERE channel = 'ROLLBACK' AND commercial_distribution_allowed = 1 ORDER BY published_at DESC LIMIT 1"
            ).fetchone()
            return {
                "current_version": current_version,
                "latest_stable_version": latest["version"] if latest else current_version,
                "update_available": (latest["version"] != current_version) if latest else False,
                "latest_release": dict(latest) if latest else None,
                "rollback_release": dict(rollback) if rollback else None,
            }
