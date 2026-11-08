#!/usr/bin/env python3
"""
NexoraAI V14.2 Commercial Platform — Modular Backend API Router & Server (`api/app_server.py`)
----------------------------------------------------------------------------------------------
Organizes the commercial platform into distinct, modular service endpoints with RBAC,
input validation, rate limiting, and security headers:
  - Public Website & Configurable Edition Catalog (`GET /api/v1/public/editions`, `GET /api/v1/public/releases`)
  - Authentication Service (`POST /api/v1/auth/register`, `POST /api/v1/auth/login`)
  - License Service (`POST /api/v1/licenses/activate`, `POST /api/v1/licenses/verify`, `POST /api/v1/licenses/deactivate`)
  - Payment Service (`POST /api/v1/payments/checkout`, `POST /api/v1/payments/webhook`, `POST /api/v1/payments/client-claim`)
  - Download & Update Service (`POST /api/v1/downloads/authorize`, `POST /api/v1/downloads/consume`, `GET /api/v1/updates/check`)
  - Customer Dashboard Service (`GET /api/v1/customer/dashboard`, `POST /api/v1/customer/support`)
  - Private Admin Dashboard Service (`POST /api/v1/admin/pricing`, `POST /api/v1/admin/licenses/issue`,
    `POST /api/v1/admin/licenses/revoke`, `GET /api/v1/admin/analytics`, `GET /api/v1/admin/audit-logs`)
"""
import json
import os
import time
from pathlib import Path
from commercial_platform.database.db_manager import DatabaseManager
from commercial_platform.services.auth_service import AuthenticationService, SecurityError, AuthorizationError
from commercial_platform.services.license_service import LicenseService, LicenseError
from commercial_platform.services.distribution_service import DistributionService, DistributionError
from commercial_platform.services.payment_service import (
    PaymentService,
    PaymentOnboardingDisabledError,
    PaymentSecurityError,
)
from commercial_platform.services.analytics_service import AnalyticsAndSupportService, PrivacyViolationError
from commercial_platform.services.monitoring_and_tls import ProductionMonitoringService


class CommercialPlatformAPIServer:
    """
    Unified in-process & HTTP dispatchable API server with per-IP rate limiting,
    strict Role-Based Access Control (`customer` vs `admin`), and security headers.
    """
    SECURITY_HEADERS = {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Cache-Control": "no-store",
    }

    def __init__(self, db_path: Path | None = None):
        self.db = DatabaseManager(db_path) if db_path else DatabaseManager()
        self.auth = AuthenticationService(self.db)
        self.licenses = LicenseService(self.db)
        self.distribution = DistributionService(self.db)
        self.payments = PaymentService(self.db, self.licenses)
        self.analytics = AnalyticsAndSupportService(self.db)
        self.monitoring = ProductionMonitoringService(self.db, Path(__file__).resolve().parent.parent.parent)
        self._rate_buckets: dict[str, list[float]] = {}
        self.rate_limit_per_window = 60
        self.rate_window_sec = 60.0
        self._bootstrap_initial_admin_if_needed()

    def _bootstrap_initial_admin_if_needed(self):
        # Auto-bootstrap admin only if configured via env var or if running production database without any admin
        if os.environ.get("NEXORA_DISABLE_ADMIN_BOOTSTRAP") == "1":
            return
        admin_email = os.environ.get("NEXORA_ADMIN_INITIAL_EMAIL")
        admin_pass = os.environ.get("NEXORA_ADMIN_INITIAL_PASSWORD")
        if not admin_email or not admin_pass:
            return
        admin_name = os.environ.get("NEXORA_ADMIN_INITIAL_NAME", "Nexora Administrator")
        with self.db.connect() as conn:
            cur = conn.execute("SELECT user_id FROM users WHERE email = ? LIMIT 1", (admin_email.strip().lower(),))
            if cur.fetchone() is None:
                try:
                    self.auth.register_user(
                        email=admin_email,
                        password=admin_pass,
                        full_name=admin_name,
                        organization="NexoraAI Sovereign Platform",
                        role="admin",
                        ip_address="127.0.0.1",
                    )
                except Exception:
                    pass

    def _check_rate_limit(self, ip_address: str, endpoint: str):
        key = f"{ip_address}:{endpoint}"
        now = time.time()
        window = [t for t in self._rate_buckets.get(key, []) if now - t < self.rate_window_sec]
        if len(window) >= self.rate_limit_per_window:
            self.db.log_audit_event(None, "anonymous", "RATE_LIMIT_EXCEEDED", endpoint, "BLOCKED_429", ip_address, "Rate limit exceeded")
            raise SecurityError("429 Too Many Requests: Rate limit exceeded.")
        window.append(now)
        self._rate_buckets[key] = window

    def handle_request(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        headers: dict | None = None,
        ip_address: str = "127.0.0.1",
    ) -> dict:
        hdrs = headers or {}
        payload = body or {}
        try:
            self._check_rate_limit(ip_address, path)

            # 1. Public Catalog & Update Endpoints
            if method == "GET" and path == "/api/v1/health":
                health = self.monitoring.check_system_health()
                code = 200 if health["status"] == "HEALTHY" else 503
                return {"status_code": code, "headers": self.SECURITY_HEADERS, "data": health}

            if method == "GET" and path == "/api/v1/public/editions":
                return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": self.licenses.list_edition_plans()}

            if method == "GET" and path == "/api/v1/updates/check":
                ver = payload.get("current_version", "14.2.0")
                return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": self.distribution.check_for_updates(ver)}

            # 2. Authentication Endpoints
            if method == "POST" and path == "/api/v1/auth/register":
                if payload.get("role", "customer") != "customer":
                    self.db.log_audit_event(None, "anonymous", "PRIVILEGE_ESCALATION_ATTEMPT", path, "BLOCKED_403", ip_address, "Attempted public registration with admin role")
                    return {"status_code": 403, "headers": self.SECURITY_HEADERS, "error": "Public registration cannot assign administrative roles."}
                usr = self.auth.register_user(
                    email=payload.get("email", ""),
                    password=payload.get("password", ""),
                    full_name=payload.get("full_name") or payload.get("name", "Customer"),
                    organization=payload.get("organization") or payload.get("company", ""),
                    role="customer",
                    ip_address=ip_address,
                )
                return {"status_code": 201, "headers": self.SECURITY_HEADERS, "data": usr}

            if method == "POST" and path == "/api/v1/auth/login":
                ses = self.auth.authenticate(payload.get("email", ""), payload.get("password", ""), ip_address=ip_address)
                ses["user"] = {
                    "user_id": ses["user_id"],
                    "email": ses["email"],
                    "full_name": ses.get("full_name", ""),
                    "role": ses["role"],
                }
                return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": ses}

            if method == "GET" and path == "/api/v1/auth/me":
                token = hdrs.get("Authorization", "").replace("Bearer ", "")
                ses = self.auth.verify_session(token, required_role=None, ip_address=ip_address)
                ses["user"] = {
                    "user_id": ses["user_id"],
                    "email": ses["email"],
                    "full_name": ses.get("full_name", ""),
                    "role": ses["role"],
                }
                return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": ses}

            if method == "POST" and path == "/api/v1/auth/logout":
                token = hdrs.get("Authorization", "").replace("Bearer ", "")
                res = self.auth.revoke_session(token, ip_address=ip_address)
                return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": res}

            # 3. License Activation & Entitlement Endpoints
            if method == "POST" and path == "/api/v1/licenses/activate":
                act = self.licenses.activate_device(
                    license_key_token=payload.get("license_key_token", ""),
                    device_fingerprint=payload.get("device_fingerprint", ""),
                    device_name=payload.get("device_name", "Workstation"),
                    os_platform=payload.get("os_platform", "Linux"),
                    app_version=payload.get("app_version", "14.2.0"),
                    ip_address=ip_address,
                )
                self.analytics.record_event("ACTIVATION", "14.2.0", act["edition_code"], payload.get("os_platform", "Linux"), {"device_activated": True})
                return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": act}

            if method == "POST" and path == "/api/v1/licenses/verify":
                ent = self.licenses.verify_server_entitlement(
                    payload.get("license_key_token", ""),
                    payload.get("device_fingerprint", ""),
                )
                return {"status_code": 200 if ent["entitled"] else 403, "headers": self.SECURITY_HEADERS, "data": ent}

            # 4. Authenticated Customer Endpoints
            if path.startswith("/api/v1/customer/") or path.startswith("/api/v1/downloads/") or path.startswith("/api/v1/payments/checkout") or path.startswith("/api/v1/payments/client-claim"):
                token = hdrs.get("Authorization", "").replace("Bearer ", "")
                session = self.auth.verify_session(token, required_role=None, ip_address=ip_address)
                uid = session["user_id"]

                if method == "GET" and path == "/api/v1/customer/dashboard":
                    with self.db.connect() as conn:
                        lics = self.licenses.get_customer_licenses(uid)
                        devs = [
                            dict(r)
                            for r in conn.execute(
                                "SELECT d.* FROM device_activations d JOIN licenses l ON d.license_id = l.license_id WHERE l.user_id = ?",
                                (uid,),
                            ).fetchall()
                        ]
                        orders = [dict(r) for r in conn.execute("SELECT * FROM orders WHERE user_id = ?", (uid,)).fetchall()]
                        invoices = [dict(r) for r in conn.execute("SELECT * FROM invoices WHERE user_id = ?", (uid,)).fetchall()]
                        tickets = self.analytics.list_customer_tickets(uid)
                    return {
                        "status_code": 200,
                        "headers": self.SECURITY_HEADERS,
                        "data": {
                            "profile": session,
                            "licenses": lics,
                            "devices": devs,
                            "orders": orders,
                            "invoices": invoices,
                            "support_tickets": tickets,
                            "available_releases": self.distribution.list_releases(include_quarantined_for_admin=False),
                        },
                    }

                if method == "GET" and path == "/api/v1/customer/profile":
                    return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": session}

                if method == "POST" and path == "/api/v1/customer/profile":
                    updated = self.auth.update_profile(uid, payload.get("full_name", ""), payload.get("organization", ""), ip_address=ip_address)
                    return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": updated}

                if method == "GET" and path == "/api/v1/customer/licenses":
                    lics = self.licenses.get_customer_licenses(uid)
                    return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": lics}

                if method == "POST" and path == "/api/v1/customer/devices/deactivate":
                    deact = self.licenses.deactivate_device(
                        user_id=uid,
                        license_id=payload["license_id"],
                        device_fingerprint=payload["device_fingerprint"],
                        is_admin=False,
                        ip_address=ip_address,
                    )
                    return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": deact}

                if method == "GET" and path == "/api/v1/customer/support":
                    tkts = self.analytics.list_customer_tickets(uid)
                    return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": tkts}

                if method == "POST" and path == "/api/v1/customer/support":
                    tkt = self.analytics.create_support_ticket(
                        uid,
                        payload["subject"],
                        payload.get("category", "General"),
                        payload["message"],
                        payload.get("priority", "NORMAL"),
                    )
                    return {"status_code": 201, "headers": self.SECURITY_HEADERS, "data": tkt}

                if method == "POST" and path == "/api/v1/downloads/authorize":
                    dl = self.distribution.authorize_download(uid, payload["license_id"], payload["release_id"], ip_address=ip_address)
                    return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": dl}

                if method == "POST" and path == "/api/v1/downloads/consume":
                    stream_info = self.distribution.consume_download_token(payload["download_token"], ip_address=ip_address)
                    self.analytics.record_event("DOWNLOAD", stream_info["version"], None, None, {"release_id": stream_info["release_id"]})
                    return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": stream_info}

                if method == "POST" and path == "/api/v1/payments/checkout":
                    ord_info = self.payments.create_checkout_order(
                        uid,
                        payload["edition_code"],
                        payload.get("payment_provider", "stripe_adapter"),
                        payload.get("card_data_if_any"),
                        ip_address=ip_address,
                    )
                    return {"status_code": 201, "headers": self.SECURITY_HEADERS, "data": ord_info}

                if method == "POST" and path == "/api/v1/payments/client-claim":
                    self.payments.reject_client_reported_payment_claim(uid, payload.get("order_id", "ord_unknown"), ip_address=ip_address)

            # 5. Server-to-Server Payment Webhook Endpoint
            if method == "POST" and path == "/api/v1/payments/webhook":
                res = self.payments.process_signed_webhook(
                    raw_body=payload.get("raw_body", ""),
                    signature_header=hdrs.get("X-Webhook-Signature", ""),
                    ip_address=ip_address,
                )
                return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": res}

            # 6. Private Administrator Endpoints (Strict RBAC: `required_role='admin'`)
            if path.startswith("/api/v1/admin/"):
                token = hdrs.get("Authorization", "").replace("Bearer ", "")
                admin_ses = self.auth.verify_session(token, required_role="admin", ip_address=ip_address)
                aid = admin_ses["user_id"]

                if method == "GET" and path == "/api/v1/admin/customers":
                    custs = self.auth.list_customers(
                        limit=int(payload.get("limit", 100)),
                        offset=int(payload.get("offset", 0)),
                    )
                    return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": custs}

                if method == "POST" and path == "/api/v1/admin/customers/toggle-status":
                    res = self.auth.toggle_user_active(
                        admin_user_id=aid,
                        target_user_id=payload["target_user_id"],
                        is_active=bool(payload["is_active"]),
                        ip_address=ip_address,
                    )
                    return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": res}

                if method == "GET" and path == "/api/v1/admin/licenses":
                    lics = self.licenses.list_all_licenses_admin(
                        limit=int(payload.get("limit", 100)),
                        offset=int(payload.get("offset", 0)),
                    )
                    return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": lics}

                if method == "POST" and path == "/api/v1/admin/licenses/issue":
                    lic = self.licenses.issue_license(
                        user_id=payload["user_id"],
                        edition_code=payload["edition_code"],
                        subscription_status=payload.get("subscription_status", "ACTIVE"),
                        duration_days=int(payload.get("duration_days", 365)),
                        custom_max_devices=payload.get("custom_max_devices"),
                        actor_id=aid,
                        actor_role="admin",
                        ip_address=ip_address,
                    )
                    return {"status_code": 201, "headers": self.SECURITY_HEADERS, "data": lic}

                if method == "POST" and path == "/api/v1/admin/licenses/suspend":
                    susp = self.licenses.suspend_license_by_admin(
                        admin_user_id=aid,
                        license_id=payload["license_id"],
                        reason=payload.get("reason", "Administrative suspension"),
                        ip_address=ip_address,
                    )
                    return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": susp}

                if method == "POST" and path == "/api/v1/admin/licenses/reactivate":
                    reac = self.licenses.reactivate_license_by_admin(
                        admin_user_id=aid,
                        license_id=payload["license_id"],
                        ip_address=ip_address,
                    )
                    return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": reac}

                if method == "POST" and path == "/api/v1/admin/licenses/revoke":
                    rev = self.licenses.revoke_license_by_admin(aid, payload["license_id"], payload["reason"], ip_address=ip_address)
                    return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": rev}

                if method == "GET" and path == "/api/v1/admin/devices":
                    devs = self.licenses.list_all_devices_admin(
                        limit=int(payload.get("limit", 100)),
                        offset=int(payload.get("offset", 0)),
                    )
                    return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": devs}

                if method == "POST" and path == "/api/v1/admin/devices/deactivate":
                    deact = self.licenses.deactivate_device(
                        user_id=aid,
                        license_id=payload["license_id"],
                        device_fingerprint=payload["device_fingerprint"],
                        is_admin=True,
                        ip_address=ip_address,
                    )
                    return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": deact}

                if method == "GET" and path == "/api/v1/admin/releases":
                    rels = self.distribution.list_releases(include_quarantined_for_admin=True)
                    return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": rels}

                if method == "GET" and path == "/api/v1/admin/support/tickets":
                    tkts = self.analytics.list_all_tickets_admin(
                        limit=int(payload.get("limit", 100)),
                        offset=int(payload.get("offset", 0)),
                        status_filter=payload.get("status"),
                    )
                    return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": tkts}

                if method == "POST" and path == "/api/v1/admin/support/reply":
                    rep = self.analytics.reply_support_ticket(
                        admin_user_id=aid,
                        ticket_id=payload["ticket_id"],
                        response_text=payload["response"],
                        status=payload.get("status", "RESOLVED"),
                        ip_address=ip_address,
                    )
                    return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": rep}

                if method == "POST" and path == "/api/v1/admin/pricing":
                    updated = self.licenses.update_edition_pricing_by_admin(
                        admin_user_id=aid,
                        edition_code=payload["edition_code"],
                        price_cents=payload.get("price_cents"),
                        currency=payload.get("currency", "USD"),
                        max_devices=payload.get("max_devices"),
                        api_rate_limit_per_min=payload.get("api_rate_limit_per_min"),
                        ip_address=ip_address,
                    )
                    return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": updated}

                if method == "POST" and path == "/api/v1/admin/payments/onboarding":
                    st = self.payments.set_payment_onboarding_state_by_admin(aid, bool(payload["enabled"]), ip_address=ip_address)
                    return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": st}

                if method == "GET" and path == "/api/v1/admin/analytics":
                    return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": self.analytics.get_admin_analytics_summary()}

                if method == "GET" and path == "/api/v1/admin/monitoring":
                    rep = self.monitoring.get_admin_monitoring_report()
                    return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": rep}

                if method == "GET" and path == "/api/v1/admin/audit-logs":
                    with self.db.connect() as conn:
                        logs = [dict(r) for r in conn.execute("SELECT * FROM audit_logs ORDER BY rowid DESC LIMIT 100").fetchall()]
                    return {"status_code": 200, "headers": self.SECURITY_HEADERS, "data": logs}

                if method == "POST" and path == "/api/v1/admin/database/backup":
                    tag = payload.get("tag", "manual")
                    b_info = self.db.create_backup(tag=tag)
                    self.db.log_audit_event(aid, "admin", "DATABASE_BACKUP_CREATED", b_info["backup_file"], "SUCCESS", ip_address, f"SHA-256: {b_info['sha256']}")
                    return {"status_code": 201, "headers": self.SECURITY_HEADERS, "data": b_info}

            return {"status_code": 404, "headers": self.SECURITY_HEADERS, "error": f"Endpoint not found: {method} {path}"}

        except AuthorizationError as exc:
            return {"status_code": 403, "headers": self.SECURITY_HEADERS, "error": str(exc)}
        except (SecurityError, LicenseError, DistributionError, PaymentSecurityError, PrivacyViolationError) as exc:
            code = 429 if "429" in str(exc) else 403
            return {"status_code": code, "headers": self.SECURITY_HEADERS, "error": str(exc)}
        except PaymentOnboardingDisabledError as exc:
            return {"status_code": 503, "headers": self.SECURITY_HEADERS, "error": str(exc)}
        except Exception as exc:
            return {"status_code": 400, "headers": self.SECURITY_HEADERS, "error": str(exc)}
