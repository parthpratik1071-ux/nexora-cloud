# NexoraAI V14.2 Commercial Platform — API & Database Architecture Documentation

## 1. Modular Service Architecture (Section 13)
```text
commercial_platform/
├── database/
│   ├── schema.sql                # 12 Relational Tables (SQLite 3.35+ / PostgreSQL 14+ compatible)
│   └── db_manager.py             # Migrations, Configurable Editions, Release Quarantine, Backup/Restore
├── services/
│   ├── auth_service.py           # PBKDF2-HMAC-SHA256 (600k iter), Brute-Force Lockout, Session HMAC, RBAC
│   ├── license_service.py        # 5 Editions, Server Signing, Device Limits, Public-Digest Offline Leases
│   ├── distribution_service.py   # Signed Single-Use Download Tokens, SHA-256 Verification, Qwen Quarantine
│   ├── payment_service.py        # Disabled-by-Default Payment Adapter, Webhook HMAC, Idempotency, Invoices
│   └── analytics_service.py      # Privacy-Conscious Telemetry (Zero Prompt/Chat Collection Enforced)
├── api/
│   └── app_server.py             # Unified REST API Router, Rate Limiter (60 req/min), Security Headers
├── desktop/
│   └── nexora_desktop_app.py     # Native Desktop App (PySide6 / Tkinter / Headless CLI) + Local SQLite History
├── web/
│   └── index.html                # Self-Contained 14-Page Commercial Website, Customer Portal & Admin Console
├── legal/
│   └── LEGAL_DRAFTS_BUNDLE.md    # Draft EULA, ToS, Privacy Policy, AUP, Refund Policy, 3P Notices
└── docs/
    ├── IP_COMPLIANCE_REPORT.md
    ├── SECURITY_ASSESSMENT_REPORT.md
    ├── API_AND_DATABASE_DOCUMENTATION.md
    └── DEPLOYMENT_AND_INSTALLATION_GUIDE.md
```

## 2. REST API Endpoints Reference

| Method & Endpoint | Access Role | Description |
| :--- | :--- | :--- |
| `GET /api/v1/public/editions` | `Public` | Returns all 5 commercial editions (`personal`, `professional`, `developer`, `enterprise`, `api`) and their admin-configured pricing/limits. |
| `GET /api/v1/updates/check` | `Public` | Returns latest stable V14.2 release and rollback manifest with SHA-256 checksums. |
| `POST /api/v1/auth/register` | `Public` | Registers a `customer` account (`role='admin'` is blocked on public registration). |
| `POST /api/v1/auth/login` | `Public` | Authenticates via PBKDF2-HMAC-SHA256 and returns a signed bearer session token + CSRF token. |
| `POST /api/v1/licenses/activate` | `Device` | Validates license status & device limit, registers `device_fingerprint`, and returns an `offline_lease`. |
| `POST /api/v1/licenses/verify` | `Device` | Server-side entitlement check verifying active license and active device registration. |
| `GET /api/v1/customer/dashboard` | `Customer` | Returns customer profile, licenses, registered devices, orders, invoices, tickets, and authorized downloads. |
| `POST /api/v1/customer/support` | `Customer` | Submits a customer support ticket. |
| `POST /api/v1/downloads/authorize` | `Customer` | Issues a 15-minute single-use signed download token (blocks quarantined Qwen LoRA adapter). |
| `POST /api/v1/downloads/consume` | `Customer` | Verifies and consumes a single-use download token (`used_count = 1`). |
| `POST /api/v1/payments/checkout` | `Customer` | Creates a `PENDING` order when payment onboarding is enabled; rejects raw card data (`403`). |
| `POST /api/v1/payments/client-claim` | `Customer` | Always returns `403` — paid licenses are never activated from client assertions. |
| `POST /api/v1/payments/webhook` | `Webhook` | Verifies `X-Webhook-Signature` (`HMAC-SHA256`), enforces idempotency (`webhook_events`), and issues/revokes licenses. |
| `POST /api/v1/admin/pricing` | `Admin Only` | Configures edition price (`price_cents`, `currency`), device limits, and API rate limits. |
| `POST /api/v1/admin/licenses/issue` | `Admin Only` | Issues a new signed license key (`NXRA-V142-...`) to a customer. |
| `POST /api/v1/admin/licenses/revoke` | `Admin Only` | Revokes a license and deactivates all associated devices. |
| `POST /api/v1/admin/payments/onboarding` | `Admin Only` | Enables or disables live payment checkout after legal/merchant onboarding. |
| `GET /api/v1/admin/analytics` | `Admin Only` | Returns privacy-safe aggregate metrics (downloads, activations, revenue, open tickets). |
| `GET /api/v1/admin/audit-logs` | `Admin Only` | Returns immutable security and administrative audit logs. |
