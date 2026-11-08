#!/usr/bin/env python3
"""
NexoraAI V14.2 Commercial Platform — Payment Infrastructure Abstraction (`payment_service.py`)
----------------------------------------------------------------------------------------------
Implements Section 9 requirements:
  - Provider-agnostic payment abstraction supporting future integration with Stripe, Razorpay, or Paddle.
  - DISABLED BY DEFAULT (`payment_integration_enabled = False`) until the business owner completes
    legal entity onboarding and merchant eligibility verification.
  - Server-side payment verification & HMAC-SHA256 webhook signature validation.
  - Idempotency protection via `webhook_events` (`webhook_event_id` primary key deduplication).
  - Order records (`PENDING`, `PAID_VERIFIED`, `FAILED`, `REFUNDED`), invoice generation, and refund handling.
  - Zero storage of raw payment card numbers (`PAN`), CVV, or expiration dates.
  - Strict rejection of client-reported payment success (`activate_from_client_claim` is forbidden).
"""
import hashlib
import hmac
import json
import os
import secrets
import uuid
from commercial_platform.database.db_manager import DatabaseManager, utc_now
from commercial_platform.services.license_service import LicenseService


class PaymentOnboardingDisabledError(Exception):
    pass


class PaymentSecurityError(Exception):
    pass


class PaymentService:
    def __init__(self, db: DatabaseManager, license_service: LicenseService):
        self.db = db
        self.license_service = license_service
        # Payment processing is strictly disabled until legal/merchant onboarding is completed
        self.payment_integration_enabled: bool = (
            os.environ.get("NEXORA_ENABLE_LIVE_PAYMENTS", "false").lower() == "true"
        )
        self._webhook_secret = os.environ.get("NEXORA_PAYMENT_WEBHOOK_SECRET") or secrets.token_hex(32)

    def set_payment_onboarding_state_by_admin(self, admin_user_id: str, enabled: bool, ip_address: str = "127.0.0.1") -> dict:
        self.payment_integration_enabled = bool(enabled)
        self.db.log_audit_event(
            admin_user_id,
            "admin",
            "PAYMENT_ONBOARDING_STATE_CHANGE",
            "payment_service",
            "ENABLED" if enabled else "DISABLED",
            ip_address,
            f"Admin set payment_integration_enabled={enabled}",
        )
        return {"payment_integration_enabled": self.payment_integration_enabled}

    def create_checkout_order(
        self,
        user_id: str,
        edition_code: str,
        payment_provider: str = "stripe_adapter",
        card_data_if_any: dict | None = None,
        ip_address: str = "127.0.0.1",
    ) -> dict:
        # Never accept or store payment-card information on our server
        if card_data_if_any:
            self.db.log_audit_event(user_id, "customer", "PCI_CARD_DATA_REJECTED", edition_code, "BLOCKED", ip_address, "Rejected raw card data submission")
            raise PaymentSecurityError("PCI Security Policy: Never submit raw payment card details to NexoraAI servers.")

        if not self.payment_integration_enabled:
            self.db.log_audit_event(user_id, "customer", "CHECKOUT_ATTEMPT_WHILE_DISABLED", edition_code, "BLOCKED_ONBOARDING_PENDING", ip_address, "Payment gateway disabled pending legal onboarding")
            raise PaymentOnboardingDisabledError(
                "Payment processing is currently disabled until merchant eligibility, tax registration, "
                "and legal onboarding are completed by an authorized business representative."
            )

        with self.db.connect() as conn:
            plan = conn.execute("SELECT * FROM pricing_plans WHERE edition_code = ?", (edition_code,)).fetchone()
            if plan is None:
                raise ValueError(f"Invalid edition: {edition_code}")
            if not plan["pricing_configured_by_admin"] or plan["price_cents"] is None:
                raise ValueError(f"Pricing for '{edition_code}' has not yet been configured by the administrator.")

            order_id = f"ord_{uuid.uuid4().hex[:16]}"
            now = utc_now()
            conn.execute(
                """
                INSERT INTO orders (
                    order_id, user_id, edition_code, amount_cents, currency,
                    payment_provider, provider_reference_id, status, license_id_issued,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, NULL, 'PENDING', NULL, ?, ?)
                """,
                (order_id, user_id, edition_code, int(plan["price_cents"]), plan["currency"], payment_provider, now, now),
            )
            conn.commit()

        self.db.log_audit_event(user_id, "customer", "ORDER_CREATED", order_id, "PENDING", ip_address, f"Created order for {edition_code}")
        return {
            "order_id": order_id,
            "user_id": user_id,
            "edition_code": edition_code,
            "amount_cents": int(plan["price_cents"]),
            "currency": plan["currency"],
            "status": "PENDING",
        }

    def reject_client_reported_payment_claim(self, user_id: str, order_id: str, ip_address: str = "127.0.0.1"):
        """
        Explicit guard: Never activate a paid license merely because the client reports a successful payment.
        """
        self.db.log_audit_event(
            user_id,
            "customer",
            "CLIENT_PAYMENT_CLAIM_REJECTED",
            order_id,
            "BLOCKED_SECURITY_POLICY",
            ip_address,
            "Client attempted to self-confirm payment without signed provider webhook.",
        )
        raise PaymentSecurityError(
            "Security Policy Violation: Paid licenses are never activated from client-side payment assertions. "
            "A cryptographically signed server-to-server provider webhook is mandatory."
        )

    def sign_webhook_payload_for_verification(self, raw_body: str) -> str:
        return hmac.new(self._webhook_secret.encode("utf-8"), raw_body.encode("utf-8"), hashlib.sha256).hexdigest()

    def process_signed_webhook(self, raw_body: str, signature_header: str, ip_address: str = "127.0.0.1") -> dict:
        expected_sig = self.sign_webhook_payload_for_verification(raw_body)
        if not signature_header or not hmac.compare_digest(signature_header, expected_sig):
            self.db.log_audit_event(None, "webhook", "WEBHOOK_SIGNATURE_INVALID", "payment_webhook", "REJECTED", ip_address, "Invalid HMAC signature")
            raise PaymentSecurityError("Invalid webhook signature.")

        event = json.loads(raw_body)
        event_id = event.get("event_id")
        event_type = event.get("event_type")
        order_id = event.get("order_id")
        provider = event.get("provider", "stripe_adapter")
        if not event_id or not event_type or not order_id:
            raise ValueError("Webhook payload missing event_id, event_type, or order_id.")

        payload_sha = hashlib.sha256(raw_body.encode("utf-8")).hexdigest()

        with self.db.connect() as conn:
            # Idempotency check
            dup = conn.execute("SELECT webhook_event_id FROM webhook_events WHERE webhook_event_id = ?", (event_id,)).fetchone()
            if dup is not None:
                return {"status": "IDEMPOTENT_DUPLICATE_IGNORED", "event_id": event_id, "order_id": order_id}

            ord_row = conn.execute("SELECT * FROM orders WHERE order_id = ?", (order_id,)).fetchone()
            if ord_row is None:
                raise ValueError(f"Order not found: {order_id}")

            conn.execute(
                "INSERT INTO webhook_events (webhook_event_id, provider, event_type, payload_sha256, processed_at) VALUES (?, ?, ?, ?, ?)",
                (event_id, provider, event_type, payload_sha, utc_now()),
            )
            conn.commit()

            if event_type == "payment.succeeded":
                lic = self.license_service.issue_license(
                    user_id=ord_row["user_id"],
                    edition_code=ord_row["edition_code"],
                    subscription_status="ACTIVE",
                    actor_id="webhook_verifier",
                    actor_role="admin",
                    ip_address=ip_address,
                )
                inv_id = f"inv_{uuid.uuid4().hex[:16]}"
                inv_num = f"INV-V142-{int(uuid.uuid4().int % 900000 + 100000)}"
                conn.execute(
                    "UPDATE orders SET status = 'PAID_VERIFIED', provider_reference_id = ?, license_id_issued = ?, updated_at = ? WHERE order_id = ?",
                    (event_id, lic["license_id"], utc_now(), order_id),
                )
                conn.execute(
                    """
                    INSERT INTO invoices (invoice_id, order_id, user_id, invoice_number, amount_cents, currency, status, issued_at)
                    VALUES (?, ?, ?, ?, ?, ?, 'PAID', ?)
                    """,
                    (inv_id, order_id, ord_row["user_id"], inv_num, ord_row["amount_cents"], ord_row["currency"], utc_now()),
                )
                conn.commit()
                return {
                    "status": "PAID_VERIFIED",
                    "order_id": order_id,
                    "license_id": lic["license_id"],
                    "license_key_token": lic["license_key_token"],
                    "invoice_number": inv_num,
                }

            elif event_type == "payment.refunded":
                conn.execute("UPDATE orders SET status = 'REFUNDED', updated_at = ? WHERE order_id = ?", (utc_now(), order_id))
                conn.execute("UPDATE invoices SET status = 'REFUNDED' WHERE order_id = ?", (order_id,))
                if ord_row["license_id_issued"]:
                    self.license_service.revoke_license_by_admin(
                        "webhook_refund_handler",
                        ord_row["license_id_issued"],
                        f"Order {order_id} refunded via provider webhook {event_id}",
                        ip_address,
                    )
                conn.commit()
                return {"status": "REFUNDED_AND_LICENSE_REVOKED", "order_id": order_id}

            elif event_type == "payment.failed":
                conn.execute("UPDATE orders SET status = 'FAILED', updated_at = ? WHERE order_id = ?", (utc_now(), order_id))
                conn.commit()
                return {"status": "FAILED_RECORDED", "order_id": order_id}

        raise ValueError(f"Unsupported webhook event_type: {event_type}")
