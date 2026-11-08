# NexoraAI V14.2 Cloud Commercial Service — Comprehensive API Documentation

## Overview
The NexoraAI V14.2 Cloud Commercial Service is a high-security, zero-budget, lightweight backend designed to manage customer accounts, commercial licensing, device activations, secure installer distribution, and administrative operations.

- **Base URL:** `https://nexora.example.com` (or `http://localhost:8080` in local/container dev)
- **API Version:** `v1` (`/api/v1/...`)
- **Protocol:** HTTP/1.1 or HTTP/2 over TLS 1.3
- **Rate Limit:** 60 requests per minute per IP address (returns `429 Too Many Requests` with `Retry-After: 60`)
- **Response Format:** JSON (`application/json; charset=utf-8`)
- **Security Headers:** All responses include `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Permissions-Policy`.

---

## Authentication & Session Architecture

### Session Tokens
Authentication uses cryptographically signed Bearer tokens generated via HMAC-SHA256. Tokens are transmitted in the HTTP Authorization header:
```http
Authorization: Bearer <session_token>
```

### Password Hashing
- Algorithm: `PBKDF2-HMAC-SHA256`
- Iterations: `600,000`
- Salt: 16-byte cryptographically secure random salt (`os.urandom(16)`)
- Brute-Force Lockout: 5 consecutive failed attempts trigger an automated 15-minute account lockout (`403 Forbidden`).

---

## 1. Public Endpoints (No Authentication Required)

### 1.1 Health Probe
`GET /api/v1/health`
Checks SQLite database responsiveness, model checkpoint integrity (SHA-256 match), and memory usage.

**Response `200 OK`:**
```json
{
  "data": {
    "status": "HEALTHY",
    "version": "14.2.0",
    "database_online": true,
    "native_v14_2_checkpoint_present": true,
    "qwen_lora_quarantine_enforced": true,
    "process_rss_mb": 42.15,
    "uptime_seconds": 1284.5,
    "logged_error_events_count": 0
  }
}
```

### 1.2 Commercial Editions & Pricing Catalog
`GET /api/v1/public/editions`
Retrieves the 5 standardized commercial editions and their administrator-configured pricing.

**Response `200 OK`:**
```json
{
  "data": [
    {
      "edition_code": "personal",
      "display_name": "Personal Edition",
      "billing_model": "PERPETUAL_OR_ANNUAL_CONFIGURABLE",
      "price_cents": null,
      "currency": "USD",
      "pricing_configured_by_admin": 0,
      "max_devices": 1,
      "api_rate_limit_per_min": 0,
      "offline_lease_days": 30,
      "commercial_use_permitted": 0,
      "features": [
        "Individual non-commercial licensed usage",
        "100% local Native NexoraAI V14.2 inference (15,684,488 params)",
        "Desktop chat interface with local SQLite history",
        "SymPy symbolic math verification & basic generation controls"
      ]
    },
    {
      "edition_code": "professional",
      "display_name": "Professional Edition",
      "billing_model": "ANNUAL_SUBSCRIPTION_CONFIGURABLE",
      "price_cents": 19900,
      "currency": "USD",
      "pricing_configured_by_admin": 1,
      "max_devices": 2,
      "api_rate_limit_per_min": 0,
      "offline_lease_days": 30,
      "commercial_use_permitted": 1,
      "features": [
        "Up to 2 registered devices",
        "Semantic Memory 2.2 (99.04% precision, typo-tolerant)",
        "Full sampling & KV-cache controls",
        "5-Language restricted code verification sandbox"
      ]
    }
  ]
}
```

### 1.3 Updates Check
`GET /api/v1/updates/check?current_version=14.2.0`
Checks for available desktop software updates and provides rollback manifests.

**Response `200 OK`:**
```json
{
  "data": {
    "current_client_version": "14.2.0",
    "latest_stable_version": "14.2.0",
    "update_available": false,
    "release_id": "rel_v14_1_0_native_desktop",
    "sha256_checksum": "d285ab0e4e24916f27a7d7ec4b846c6a5bbc00e6f92d455f02083f851c073e56",
    "size_bytes": 62741608
  }
}
```

---

## 2. Authentication Endpoints

### 2.1 Customer Registration
`POST /api/v1/auth/register`
Creates a new customer account. Public registration cannot assign administrative roles (`role='admin'` is rejected with `403 Forbidden`).

**Request Body:**
```json
{
  "email": "customer@example.com",
  "password": "CustomerSecurePassword2026!",
  "full_name": "Dr. Jane Doe",
  "organization": "Quantum Labs"
}
```

**Response `201 Created`:**
```json
{
  "data": {
    "user_id": "usr_998124ab",
    "email": "customer@example.com",
    "full_name": "Dr. Jane Doe",
    "role": "customer",
    "created_at": "2026-11-07T12:00:00Z"
  }
}
```

### 2.2 Session Login
`POST /api/v1/auth/login`
Authenticates credentials, generates an active session token, and records login audit log.

**Request Body:**
```json
{
  "email": "customer@example.com",
  "password": "CustomerSecurePassword2026!"
}
```

**Response `200 OK`:**
```json
{
  "data": {
    "session_token": "eyJhbGciOi...",
    "csrf_token": "csrf_8891240a...",
    "user": {
      "user_id": "usr_998124ab",
      "email": "customer@example.com",
      "full_name": "Dr. Jane Doe",
      "role": "customer"
    },
    "expires_at_ts": 1794056400.0
  }
}
```

### 2.3 Whoami / Me Probe
`GET /api/v1/auth/me`
Header: `Authorization: Bearer <session_token>`

**Response `200 OK`:**
```json
{
  "data": {
    "user": {
      "user_id": "usr_998124ab",
      "email": "customer@example.com",
      "full_name": "Dr. Jane Doe",
      "role": "customer",
      "is_active": 1,
      "analytics_opt_in": 1
    }
  }
}
```

### 2.4 Session Logout
`POST /api/v1/auth/logout`
Header: `Authorization: Bearer <session_token>`
Immediately revokes the session token in SQLite.

**Response `200 OK`:**
```json
{
  "data": {
    "revoked": true,
    "message": "Session revoked successfully."
  }
}
```

---

## 3. Customer Service Endpoints

### 3.1 Customer Dashboard Overview
`GET /api/v1/customer/dashboard`
Header: `Authorization: Bearer <session_token>`
Retrieves all customer entitlements, licenses, registered devices, invoices, and download rights.

**Response `200 OK`:**
```json
{
  "data": {
    "profile": {
      "user_id": "usr_998124ab",
      "email": "customer@example.com",
      "full_name": "Dr. Jane Doe"
    },
    "licenses": [
      {
        "id": "lic_prof_8821a",
        "edition": "professional",
        "key": "NXRA-V142-PROF-9A4F-2C1E-88B0-7D3A",
        "status": "ACTIVE",
        "subStatus": "ACTIVE",
        "maxDevices": 2,
        "expires": "2027-11-07"
      }
    ],
    "devices": [
      {
        "id": "act_01",
        "licenseId": "lic_prof_8821a",
        "fingerprint": "FP-LINUX-WS-01",
        "name": "Linux Workstation",
        "status": "ACTIVE"
      }
    ],
    "invoices": [],
    "support_tickets": []
  }
}
```

### 3.2 Customer Device Deactivation
`POST /api/v1/customer/devices/deactivate`
Header: `Authorization: Bearer <session_token>`
Frees up an active seat slot by deactivating a workstation registration.

**Request Body:**
```json
{
  "license_id": "lic_prof_8821a",
  "hardware_fingerprint": "FP-LINUX-WS-01"
}
```

**Response `200 OK`:**
```json
{
  "data": {
    "deactivated": true,
    "license_id": "lic_prof_8821a",
    "hardware_fingerprint": "FP-LINUX-WS-01"
  }
}
```

### 3.3 Customer Support Tickets
- `GET /api/v1/customer/support`: Lists support tickets for current authenticated customer.
- `POST /api/v1/customer/support`: Creates a new support ticket.

**Request Body (`POST`):**
```json
{
  "subject": "SymPy verification on custom equations",
  "message": "How do I configure additional SymPy algebraic symbols in the desktop application?",
  "priority": "NORMAL",
  "category": "Technical Guidance"
}
```

**Response `201 Created`:**
```json
{
  "data": {
    "ticket_id": "tkt_8124ba",
    "subject": "SymPy verification on custom equations",
    "status": "OPEN",
    "priority": "NORMAL",
    "created_at": "2026-11-07T12:30:00Z"
  }
}
```

---

## 4. Device Activation & Offline Licensing

### 4.1 Device Activation
`POST /api/v1/licenses/activate`
Activates a local desktop instance, verifies per-edition seat limits, registers device fingerprint in SQLite, and returns a signed offline lease digest.

**Request Body:**
```json
{
  "license_key": "NXRA-V142-PROF-9A4F-2C1E-88B0-7D3A",
  "hardware_fingerprint": "FP-LINUX-WS-02",
  "device_name": "Secondary Laptop",
  "client_version": "14.2.0",
  "os_platform": "Linux-x86_64"
}
```

**Response `200 OK`:**
```json
{
  "data": {
    "activation_id": "act_881290",
    "license_id": "lic_prof_8821a",
    "edition_code": "professional",
    "max_devices": 2,
    "active_devices_count": 2,
    "offline_lease": {
      "license_key": "NXRA-V142-PROF-9A4F-2C1E-88B0-7D3A",
      "device_fingerprint": "FP-LINUX-WS-02",
      "lease_duration_days": 30,
      "lease_expires_at": "2026-12-07T12:00:00Z",
      "server_lease_digest": "4c98f12a09b...",
      "public_digest_algorithm": "SHA256(license_id:device_fp:expires_ts:salt)"
    }
  }
}
```
*Note on Client Key Security: Zero private keys are stored on the desktop client. Offline verification validates digest format against server-issued signed leases.*

### 4.2 Online License Verification
`POST /api/v1/licenses/verify`
Server-side heartbeat verification called periodically by the desktop app when online.

---

## 5. Protected Downloads & Storage Distribution

### 5.1 Authorize Download
`POST /api/v1/downloads/authorize`
Header: `Authorization: Bearer <session_token>`
Verifies customer license entitlement and issues a short-lived (15-minute), single-use download token.
*Legal & IP Rule: Quarantined assets (e.g. Qwen LoRA adapter) return `403 Forbidden` (`commercial_distribution_allowed = 0`).*

**Request Body:**
```json
{
  "release_id": "rel_v14_1_0_native_desktop",
  "license_key": "NXRA-V142-PROF-9A4F-2C1E-88B0-7D3A"
}
```

**Response `200 OK`:**
```json
{
  "data": {
    "release_id": "rel_v14_1_0_native_desktop",
    "version": "14.2.0",
    "download_token": "dlt_4c810b.f89012a...",
    "download_url": "/api/v1/downloads/stream?token=dlt_4c810b.f89012a...",
    "expires_in_seconds": 900,
    "sha256_checksum": "d285ab0e4e24916f27a7d7ec4b846c6a5bbc00e6f92d455f02083f851c073e56",
    "size_bytes": 62741608
  }
}
```

### 5.2 Stream Download Endpoint
`GET /api/v1/downloads/stream?token=<download_token>`
Validates token signature, ensures token has not been reused (`max_uses = 1`, `used_count = 0`), increments use count, and streams binary payload.
- When `NEXORA_STORAGE_BACKEND=s3_presigned`: Issues `302 Found` redirect to private Cloudflare R2 / AWS S3 presigned URL with zero credentials exposed to client.
- When `NEXORA_STORAGE_BACKEND=local`: Streams binary file with `Content-Type: application/octet-stream` and `X-Artifact-SHA256` header.
- Token Replay Prevention: Attempting to use the same token a second time returns `403 Forbidden` (`Download token has already been consumed`).

---

## 6. Payments & Webhooks Framework

### 6.1 Checkout Creation (Gate Protected)
`POST /api/v1/payments/checkout`
- **Default State:** Returns `503 Service Unavailable` until merchant onboarding is explicitly enabled by an administrator.
- **Card Security:** Never accepts raw credit card details (`number`, `cvv`, `pan`). Any request containing raw card fields returns `400 Bad Request` / `403 Forbidden`.

### 6.2 Signed Webhook Endpoint
`POST /api/v1/payments/webhook`
Header: `X-Webhook-Signature: <hex_hmac_sha256>`
Processes verified asynchronous order events from merchant processors (Stripe, Lemon Squeezy, Paddle).
- Signature Verification: Computes HMAC-SHA256 over raw request payload using `NEXORA_PAYMENT_WEBHOOK_SECRET`.
- Idempotency Guarantee: Records each `event_id` in `webhook_events` table; duplicate events return `200 OK` without duplicating licenses.
- Event Types:
  - `payment.succeeded`: Automatically provisions active license key and records invoice.
  - `payment.refunded`: Automatically revokes license and cascades deactivation to all associated devices.

---

## 7. Administrator Console & RBAC (`role = admin`)

All endpoints in `/api/v1/admin/*` enforce strict backend Role-Based Access Control. Any request made with a non-admin session token or unauthenticated client returns `403 Forbidden` (`RBAC_VIOLATION logged`).

### 7.1 Customer Management
- `GET /api/v1/admin/customers`: Lists all registered users, roles, active status, and creation timestamps.
- `POST /api/v1/admin/customers/toggle-status`: Activates or suspends customer account access.
  - Body: `{"user_id": "usr_...", "is_active": false}`

### 7.2 License Lifecycle Operations
- `GET /api/v1/admin/licenses`: Lists all commercial licenses across all customers.
- `POST /api/v1/admin/licenses/issue`: Issues a new cryptographically signed license to a customer.
  - Body: `{"customer_email": "customer@example.com", "edition_code": "developer"}`
- `POST /api/v1/admin/licenses/suspend`: Temporarily suspends license.
  - Body: `{"license_id": "lic_..."}`
- `POST /api/v1/admin/licenses/reactivate`: Reactivates a suspended license.
  - Body: `{"license_id": "lic_..."}`
- `POST /api/v1/admin/licenses/revoke`: Permanently revokes license and deactivates all active devices.
  - Body: `{"license_id": "lic_...", "reason": "Terms violation"}`

### 7.3 Device Management
- `GET /api/v1/admin/devices`: Lists all registered devices across all editions.
- `POST /api/v1/admin/devices/deactivate`: Deactivates an individual workstation activation.

### 7.4 Support Ticket Queue
- `GET /api/v1/admin/support/tickets`: Lists open, in-progress, and resolved support tickets.
- `POST /api/v1/admin/support/reply`: Dispatches administrator reply and updates ticket status.
  - Body: `{"ticket_id": "tkt_...", "reply_message": "...", "new_status": "RESOLVED"}`

### 7.5 Pricing Configuration
- `POST /api/v1/admin/pricing`: Updates commercial edition pricing dynamically in database.
  - Body: `{"edition_code": "professional", "price_cents": 19900, "currency": "USD"}`

### 7.6 Payment Onboarding Gate
- `POST /api/v1/admin/payments/onboarding`: Toggles payment integration kill-switch.
  - Body: `{"enabled": true, "authorized_by": "admin@nexora.local"}`

### 7.7 System Health & Telemetry
- `GET /api/v1/admin/monitoring`: Detailed real-time diagnostics: RAM usage (RSS), uptime, database WAL state, checkpoint verification status, and error logs.
- `GET /api/v1/admin/audit-logs`: Retrieves immutable security audit log trail.
- `POST /api/v1/admin/database/backup`: Triggers instant hot SQLite backup to `/backups/` and returns backup manifest with SHA-256 integrity hash.
