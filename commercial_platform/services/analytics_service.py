#!/usr/bin/env python3
"""
NexoraAI V14.2 Commercial Platform — Privacy-Conscious Analytics & Support Service (`analytics_service.py`)
-----------------------------------------------------------------------------------------------------------
Implements Section 7, Section 8 & Section 12 requirements:
  - Tracks downloads, activations, active licenses, product versions, installation failures,
    update adoption, and support requests.
  - NEVER collects private chat conversations, user prompts, or model completions by default.
  - Automatically rejects or strips any telemetry payload containing forbidden content keys
    (`prompt`, `messages`, `chat`, `completion`, `response_text`, `conversation`).
"""
import json
import uuid
from commercial_platform.database.db_manager import DatabaseManager, utc_now


FORBIDDEN_PRIVACY_KEYS = frozenset({
    "prompt", "prompts", "chat", "chat_history", "messages", "message_text",
    "completion", "response_text", "conversation", "user_input", "raw_query",
})


class PrivacyViolationError(Exception):
    pass


class AnalyticsAndSupportService:
    def __init__(self, db: DatabaseManager):
        self.db = db

    def record_event(
        self,
        event_type: str,
        product_version: str = "14.2.0",
        edition_code: str | None = None,
        os_platform: str | None = None,
        metrics: dict | None = None,
    ) -> dict:
        payload = dict(metrics or {})
        leaked_keys = set(k.lower() for k in payload.keys()) & FORBIDDEN_PRIVACY_KEYS
        if leaked_keys:
            raise PrivacyViolationError(
                f"Privacy Policy Enforcement: Analytics service refuses to collect chat or prompt fields ({sorted(leaked_keys)})."
            )

        event_id = f"evt_{uuid.uuid4().hex[:16]}"
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO analytics_events (
                    event_id, event_type, product_version, edition_code, os_platform, anonymous_metrics_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (event_id, event_type, product_version, edition_code, os_platform, json.dumps(payload), utc_now()),
            )
            conn.commit()
        return {"event_id": event_id, "event_type": event_type, "recorded": True}

    def create_support_ticket(
        self,
        user_id: str,
        subject: str,
        category: str,
        message: str,
        priority: str = "NORMAL",
    ) -> dict:
        ticket_id = f"tkt_{uuid.uuid4().hex[:12]}"
        now = utc_now()
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO support_tickets (
                    ticket_id, user_id, subject, category, priority, status, message, admin_response, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'OPEN', ?, NULL, ?, ?)
                """,
                (ticket_id, user_id, subject.strip(), category.strip(), priority, message.strip(), now, now),
            )
            conn.commit()
        self.record_event("SUPPORT_REQUEST", "14.2.0", None, None, {"priority": priority, "category": category})
        return {"ticket_id": ticket_id, "status": "OPEN", "subject": subject.strip()}

    def list_customer_tickets(self, user_id: str) -> list[dict]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM support_tickets WHERE user_id = ? ORDER BY created_at DESC",
                (user_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def list_all_tickets_admin(self, limit: int = 100, offset: int = 0, status_filter: str | None = None) -> list[dict]:
        with self.db.connect() as conn:
            query = """
                SELECT t.*, u.email AS user_email, u.full_name AS user_name
                FROM support_tickets t
                JOIN users u ON t.user_id = u.user_id
            """
            params: list = []
            if status_filter:
                query += " WHERE t.status = ?"
                params.append(status_filter)
            query += " ORDER BY t.created_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            rows = conn.execute(query, tuple(params)).fetchall()
            return [dict(r) for r in rows]

    def reply_support_ticket(
        self,
        admin_user_id: str,
        ticket_id: str,
        response_text: str,
        status: str = "RESOLVED",
        ip_address: str = "127.0.0.1",
    ) -> dict:
        clean_resp = response_text.strip()
        if not clean_resp:
            raise ValueError("Response text cannot be empty.")
        if status not in ("OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED"):
            raise ValueError(f"Invalid status: {status}")
        now = utc_now()
        with self.db.connect() as conn:
            cur = conn.execute(
                """
                UPDATE support_tickets
                SET admin_response = ?, status = ?, updated_at = ?
                WHERE ticket_id = ?
                """,
                (clean_resp, status, now, ticket_id),
            )
            if cur.rowcount == 0:
                raise ValueError(f"Support ticket not found: {ticket_id}")
            conn.commit()
            tkt = conn.execute("SELECT * FROM support_tickets WHERE ticket_id = ?", (ticket_id,)).fetchone()
            res = dict(tkt)
        self.db.log_audit_event(
            admin_user_id,
            "admin",
            "SUPPORT_TICKET_REPLY",
            ticket_id,
            status,
            ip_address,
            f"Admin replied to ticket {ticket_id} (status={status})",
        )
        return res

    def get_admin_analytics_summary(self) -> dict:
        with self.db.connect() as conn:
            by_type = {
                r["event_type"]: r["cnt"]
                for r in conn.execute("SELECT event_type, COUNT(*) AS cnt FROM analytics_events GROUP BY event_type").fetchall()
            }
            active_lics = conn.execute("SELECT COUNT(*) AS cnt FROM licenses WHERE status = 'ACTIVE'").fetchone()["cnt"]
            active_devs = conn.execute("SELECT COUNT(*) AS cnt FROM device_activations WHERE status = 'ACTIVE'").fetchone()["cnt"]
            open_tickets = conn.execute("SELECT COUNT(*) AS cnt FROM support_tickets WHERE status = 'OPEN'").fetchone()["cnt"]
            paid_orders = conn.execute(
                "SELECT COUNT(*) AS cnt, COALESCE(SUM(amount_cents), 0) AS rev FROM orders WHERE status = 'PAID_VERIFIED'"
            ).fetchone()
            return {
                "privacy_guarantee": "STRICT_NO_PROMPT_OR_CHAT_COLLECTION",
                "active_licenses_count": active_lics,
                "active_registered_devices_count": active_devs,
                "open_support_tickets_count": open_tickets,
                "verified_paid_orders_count": paid_orders["cnt"],
                "verified_revenue_cents": paid_orders["rev"],
                "events_by_type": by_type,
            }
