-- NexoraAI V14.2 Cloud Licensing & Commercial Service — Migration 001
-- Version: 14.1.0-commercial-init
-- Description: Initial commercial licensing, RBAC, device activation, orders, invoices, releases, and telemetry.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    full_name TEXT NOT NULL,
    organization TEXT DEFAULT '',
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    pbkdf2_iterations INTEGER NOT NULL DEFAULT 600000,
    role TEXT NOT NULL CHECK (role IN ('customer', 'admin')),
    is_active INTEGER NOT NULL DEFAULT 1,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until_ts REAL NOT NULL DEFAULT 0.0,
    analytics_opt_in INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_Fix_sha256 TEXT NOT NULL,
    csrf_token TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    expires_at_ts REAL NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE IF NOT EXISTS pricing_plans (
    edition_code TEXT PRIMARY KEY CHECK (edition_code IN ('personal', 'professional', 'developer', 'enterprise', 'api')),
    display_name TEXT NOT NULL,
    billing_model TEXT NOT NULL,
    price_cents INTEGER DEFAULT NULL,
    currency TEXT NOT NULL DEFAULT 'USD',
    pricing_configured_by_admin INTEGER NOT NULL DEFAULT 0,
    max_devices INTEGER NOT NULL,
    api_rate_limit_per_min INTEGER NOT NULL DEFAULT 0,
    offline_lease_days INTEGER NOT NULL DEFAULT 30,
    commercial_use_permitted INTEGER NOT NULL DEFAULT 0,
    features_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS licenses (
    license_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    edition_code TEXT NOT NULL,
    license_key_token TEXT UNIQUE NOT NULL,
    server_signature TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'EXPIRED', 'REVOKED', 'SUSPENDED')),
    subscription_status TEXT NOT NULL CHECK (subscription_status IN ('ACTIVE', 'TRIAL', 'PAST_DUE', 'CANCELED', 'PERPETUAL')),
    max_devices INTEGER NOT NULL,
    api_key_hash TEXT DEFAULT NULL,
    api_rate_limit_per_min INTEGER NOT NULL DEFAULT 0,
    issued_at TEXT NOT NULL,
    expires_at_ts REAL NOT NULL,
    revoked_reason TEXT DEFAULT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (edition_code) REFERENCES pricing_plans(edition_code)
);

CREATE TABLE IF NOT EXISTS device_activations (
    activation_id TEXT PRIMARY KEY,
    license_id TEXT NOT NULL,
    device_fingerprint TEXT NOT NULL,
    device_name TEXT NOT NULL,
    os_platform TEXT NOT NULL,
    app_version TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'DEACTIVATED')),
    offline_lease_token TEXT NOT NULL,
    activated_at TEXT NOT NULL,
    last_verified_at TEXT NOT NULL,
    UNIQUE(license_id, device_fingerprint),
    FOREIGN KEY (license_id) REFERENCES licenses(license_id)
);

CREATE TABLE IF NOT EXISTS activation_history (
    event_id TEXT PRIMARY KEY,
    license_id TEXT NOT NULL,
    device_fingerprint TEXT NOT NULL,
    action TEXT NOT NULL,
    outcome TEXT NOT NULL,
    detail TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS orders (
    order_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    edition_code TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    currency TEXT NOT NULL,
    payment_provider TEXT NOT NULL,
    provider_reference_id TEXT DEFAULT NULL,
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'PAID_VERIFIED', 'FAILED', 'REFUNDED')),
    license_id_issued TEXT DEFAULT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE IF NOT EXISTS webhook_events (
    webhook_event_id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    processed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS invoices (
    invoice_id TEXT PRIMARY KEY,
    order_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    invoice_number TEXT UNIQUE NOT NULL,
    amount_cents INTEGER NOT NULL,
    currency TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ISSUED', 'PAID', 'REFUNDED', 'VOID')),
    issued_at TEXT NOT NULL,
    FOREIGN KEY (order_id) REFERENCES orders(order_id)
);

CREATE TABLE IF NOT EXISTS product_releases (
    release_id TEXT PRIMARY KEY,
    version TEXT UNIQUE NOT NULL,
    channel TEXT NOT NULL CHECK (channel IN ('STABLE', 'ROLLBACK', 'QUARANTINED_INTERNAL')),
    component_type TEXT NOT NULL CHECK (component_type IN ('DESKTOP_AND_NATIVE_V14_1', 'NATIVE_V14_1_CHECKPOINT', 'QWEN_LORA_ADAPTER_QUARANTINED')),
    artifact_path TEXT NOT NULL,
    sha256_checksum TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    package_signature TEXT NOT NULL,
    commercial_distribution_allowed INTEGER NOT NULL DEFAULT 1,
    release_notes TEXT NOT NULL,
    published_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS download_tokens (
    token_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    license_id TEXT NOT NULL,
    release_id TEXT NOT NULL,
    token_signature TEXT NOT NULL,
    expires_at_ts REAL NOT NULL,
    used_count INTEGER NOT NULL DEFAULT 0,
    max_uses INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS support_tickets (
    ticket_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    category TEXT NOT NULL,
    priority TEXT NOT NULL CHECK (priority IN ('LOW', 'NORMAL', 'HIGH', 'ENTERPRISE_SLA')),
    status TEXT NOT NULL CHECK (status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED')),
    message TEXT NOT NULL,
    admin_response TEXT DEFAULT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS analytics_events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL CHECK (event_type IN ('DOWNLOAD', 'ACTIVATION', 'DEACTIVATION', 'HEARTBEAT', 'INSTALL_FAILURE', 'UPDATE_ADOPTION', 'SUPPORT_REQUEST')),
    product_version TEXT NOT NULL,
    edition_code TEXT DEFAULT NULL,
    os_platform TEXT DEFAULT NULL,
    anonymous_metrics_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    log_id TEXT PRIMARY KEY,
    actor_user_id TEXT DEFAULT NULL,
    actor_role TEXT NOT NULL,
    action TEXT NOT NULL,
    target_resource TEXT NOT NULL,
    status TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    details TEXT NOT NULL,
    created_at TEXT NOT NULL
);
