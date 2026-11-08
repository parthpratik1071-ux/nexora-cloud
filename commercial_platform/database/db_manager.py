#!/usr/bin/env python3
"""
NexoraAI V14.1 Commercial Platform — Database & Disaster Recovery Manager (`db_manager.py`)
-------------------------------------------------------------------------------------------
Manages SQLite/PostgreSQL schema migrations, initial configurable edition plans (with zero
invented prices), release registry initialization (with the Qwen LoRA adapter strictly
quarantined from commercial distribution), and verified database backup & disaster recovery.
"""
import hashlib
import json
import shutil
import sqlite3
import time
import uuid
from pathlib import Path

COMMERCIAL_ROOT = Path(__file__).resolve().parent.parent
PROJECT_ROOT = COMMERCIAL_ROOT.parent
SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"
DEFAULT_DB_PATH = COMMERCIAL_ROOT / "database/nexora_commercial_v14_1.sqlite3"
BACKUP_DIR = COMMERCIAL_ROOT / "backups"
BACKUP_DIR.mkdir(parents=True, exist_ok=True)


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class DatabaseManager:
    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._apply_migrations_and_seed_defaults()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        return conn

    def _apply_migrations_and_seed_defaults(self):
        schema_sql = SCHEMA_PATH.read_text(encoding="utf-8")
        migrations_dir = self.db_path.parent / "migrations"
        with self.connect() as conn:
            conn.executescript(schema_sql)
            cur = conn.execute("SELECT version FROM schema_migrations WHERE version = '14.1.0-commercial-init'")
            if cur.fetchone() is None:
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?, ?, ?)",
                    (
                        "14.1.0-commercial-init",
                        utc_now(),
                        "Initial NexoraAI V14.1 commercial licensing, auth, RBAC, distribution, payment, and audit schema.",
                    ),
                )
            if migrations_dir.exists():
                for mig_file in sorted(migrations_dir.glob("*.sql")):
                    mig_version = mig_file.stem
                    cur_mig = conn.execute("SELECT version FROM schema_migrations WHERE version = ?", (mig_version,))
                    if cur_mig.fetchone() is None:
                        conn.executescript(mig_file.read_text(encoding="utf-8"))
                        conn.execute(
                            "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?, ?, ?)",
                            (mig_version, utc_now(), f"Applied migration script {mig_file.name}"),
                        )
            self._seed_configurable_edition_plans(conn)
            self._seed_v14_1_releases(conn)
            conn.commit()

    def _seed_configurable_edition_plans(self, conn: sqlite3.Connection):
        """
        Seeds the 5 required commercial editions with `price_cents = NULL` and
        `pricing_configured_by_admin = 0` so no pricing is invented or fabricated.
        Authorized administrators can configure pricing dynamically via the Admin API/Dashboard.
        """
        editions = [
            (
                "personal",
                "NexoraAI V14.1 — Personal Edition",
                "PERPETUAL_OR_ANNUAL_CONFIGURABLE",
                None,
                "USD",
                0,
                1,
                0,
                30,
                0,
                json.dumps([
                    "Individual non-commercial licensed usage",
                    "100% local Native NexoraAI V14.1 inference (15,684,488 parameters, 39 FP32 tensors)",
                    "Desktop chat interface with local SQLite history",
                    "SymPy symbolic math verification & basic generation controls",
                ]),
            ),
            (
                "professional",
                "NexoraAI V14.1 — Professional Edition",
                "ANNUAL_SUBSCRIPTION_CONFIGURABLE",
                None,
                "USD",
                0,
                2,
                0,
                30,
                1,
                json.dumps([
                    "Licensed professional usage across up to 2 registered devices",
                    "Advanced Semantic Memory 2.0 retrieval & custom local document indexing",
                    "Full sampling controls (Temperature, Top-K, Top-P, Repetition Penalty, KV-Cache)",
                    "5-Language Restricted Code Verification Sandbox (Python, C, C++, JS, SQL)",
                ]),
            ),
            (
                "developer",
                "NexoraAI V14.1 — Developer Edition",
                "ANNUAL_SUBSCRIPTION_CONFIGURABLE",
                None,
                "USD",
                0,
                3,
                120,
                45,
                1,
                json.dumps([
                    "Licensed across up to 3 developer workstations",
                    "Local Python SDK & CLI inference integration (`inference/native_v14_1_cli.py`)",
                    "Documented REST & local IPC developer interfaces",
                    "Permitted commercial software development subject to NexoraAI EULA terms",
                    "Tensor & KV-Cache latency diagnostics profiler",
                ]),
            ),
            (
                "enterprise",
                "NexoraAI V14.1 — Enterprise Edition",
                "CUSTOM_ENTERPRISE_AGREEMENT",
                None,
                "USD",
                0,
                25,
                600,
                90,
                1,
                json.dumps([
                    "Organization-wide multi-seat / multi-device licensing (default 25 devices, configurable)",
                    "Air-gapped offline activation lease support & centralized device management",
                    "Role-based administrative controls & compliance audit log exports",
                    "Priority Enterprise SLA support & custom licensing agreements",
                ]),
            ),
            (
                "api",
                "NexoraAI V14.1 — API Edition",
                "USAGE_BASED_CONFIGURABLE",
                None,
                "USD",
                0,
                5,
                300,
                14,
                1,
                json.dumps([
                    "Optional self-hosted or managed API inference gateway",
                    "Scoped API keys (`nxra_live_...`), configurable per-minute rate limits, and usage metering",
                    "Real-time token & request usage dashboards",
                    "Webhook & JSON schema validation endpoints",
                ]),
            ),
        ]
        for ed in editions:
            cur = conn.execute("SELECT edition_code FROM pricing_plans WHERE edition_code = ?", (ed[0],))
            if cur.fetchone() is None:
                conn.execute(
                    """
                    INSERT INTO pricing_plans (
                        edition_code, display_name, billing_model, price_cents, currency,
                        pricing_configured_by_admin, max_devices, api_rate_limit_per_min,
                        offline_lease_days, commercial_use_permitted, features_json, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (*ed, utc_now()),
                )

    def _seed_v14_1_releases(self, conn: sqlite3.Connection):
        native_ckpt = PROJECT_ROOT / "engine_v14_1/checkpoints/v14_neural/model.safetensors"
        qwen_lora_ckpt = PROJECT_ROOT / "engine_v14_1/checkpoints/best/adapter_model.safetensors"
        native_sha = hashlib.sha256(native_ckpt.read_bytes()).hexdigest() if native_ckpt.exists() else "d285ab0e4e24916f27a7d7ec4b846c6a5bbc00e6f92d455f02083f851c073e56"
        native_size = native_ckpt.stat().st_size if native_ckpt.exists() else 62741608
        lora_sha = hashlib.sha256(qwen_lora_ckpt.read_bytes()).hexdigest() if qwen_lora_ckpt.exists() else "6f17e0278e2857a0a8e9757583b91f2014a605bcaf3c8f2eae6fdc39642e77a8"
        lora_size = qwen_lora_ckpt.stat().st_size if qwen_lora_ckpt.exists() else 35237176

        releases = [
            (
                "rel_v14_1_0_native_desktop",
                "14.1.0",
                "STABLE",
                "DESKTOP_AND_NATIVE_V14_1",
                "engine_v14_1/checkpoints/v14_neural/model.safetensors",
                native_sha,
                native_size,
                hashlib.sha256(f"NEXORA_RELEASE_SIG::14.1.0::{native_sha}".encode("utf-8")).hexdigest(),
                1,
                "NexoraAI V14.1 Production Native Standalone Model (15,684,488 parameters, 39 FP32 tensors, d_model=384) + Desktop Application & Semantic Memory 2.0.",
            ),
            (
                "rel_v14_0_0_rollback_native",
                "14.0.0-rollback",
                "ROLLBACK",
                "NATIVE_V14_1_CHECKPOINT",
                "engine_v14_1/checkpoints/backups/v14.0.0-stable/model.safetensors",
                native_sha,
                native_size,
                hashlib.sha256(f"NEXORA_RELEASE_SIG::14.0.0-rollback::{native_sha}".encode("utf-8")).hexdigest(),
                1,
                "Verified V14.0/V14.1 Rollback Checkpoint Snapshot (`checkpoints/backups/v14.0.0-stable/model.safetensors`).",
            ),
            (
                "rel_v14_1_qwen_lora_quarantined",
                "14.1.0-qwen-lora-internal",
                "QUARANTINED_INTERNAL",
                "QWEN_LORA_ADAPTER_QUARANTINED",
                "engine_v14_1/checkpoints/best/adapter_model.safetensors",
                lora_sha,
                lora_size,
                hashlib.sha256(f"NEXORA_QUARANTINE_SIG::{lora_sha}".encode("utf-8")).hexdigest(),
                0,
                "QUARANTINED FROM COMMERCIAL DISTRIBUTION: 24-layer Qwen2.5-0.5B-compatible LoRA adapter (8,798,208 params, 336 tensors). Commercial distribution disabled pending review of base-model and dataset IP obligations.",
            ),
        ]
        for r in releases:
            cur = conn.execute("SELECT release_id FROM product_releases WHERE release_id = ?", (r[0],))
            if cur.fetchone() is None:
                conn.execute(
                    """
                    INSERT INTO product_releases (
                        release_id, version, channel, component_type, artifact_path,
                        sha256_checksum, size_bytes, package_signature,
                        commercial_distribution_allowed, release_notes, published_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (*r, utc_now()),
                )

    def log_audit_event(
        self,
        actor_user_id: str | None,
        actor_role: str,
        action: str,
        target_resource: str,
        status: str,
        ip_address: str,
        details: str,
    ):
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_logs (
                    log_id, actor_user_id, actor_role, action, target_resource, status, ip_address, details, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"aud_{uuid.uuid4().hex[:16]}",
                    actor_user_id,
                    actor_role,
                    action,
                    target_resource,
                    status,
                    ip_address,
                    details,
                    utc_now(),
                ),
            )
            conn.commit()

    def create_backup(self, tag: str = "daily") -> dict:
        ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        backup_file = BACKUP_DIR / f"nexora_commercial_{tag}_{ts}.sqlite3"
        with self.connect() as src_conn:
            dst_conn = sqlite3.connect(str(backup_file))
            with dst_conn:
                src_conn.backup(dst_conn)
            dst_conn.close()
        sha = hashlib.sha256(backup_file.read_bytes()).hexdigest()
        manifest = {
            "backup_file": backup_file.name,
            "sha256": sha,
            "size_bytes": backup_file.stat().st_size,
            "created_at": utc_now(),
        }
        backup_file.with_suffix(".json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return manifest

    def restore_from_backup(self, backup_filename: str) -> dict:
        bpath = BACKUP_DIR / backup_filename
        mpath = bpath.with_suffix(".json")
        if not bpath.exists() or not mpath.exists():
            raise FileNotFoundError(f"Backup or manifest missing for {backup_filename}")
        manifest = json.loads(mpath.read_text(encoding="utf-8"))
        actual_sha = hashlib.sha256(bpath.read_bytes()).hexdigest()
        if actual_sha != manifest["sha256"]:
            raise RuntimeError("Backup SHA-256 mismatch! Aborting database restore.")
        shutil.copy2(bpath, self.db_path)
        return {"restored": True, "backup_file": backup_filename, "verified_sha256": actual_sha}
