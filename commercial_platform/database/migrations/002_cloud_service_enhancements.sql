-- NexoraAI V14.2 Cloud Licensing & Commercial Service — Migration 002
-- Version: 002_cloud_service_enhancements
-- Description: Production indexes, operational reporting views, and device seat usage analytics.

-- High-performance indexes for sessions, tokens, and audit queries
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_Fix_sha256);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_download_tokens_sig ON download_tokens(token_signature);
CREATE INDEX IF NOT EXISTS idx_licenses_user_id ON licenses(user_id);
CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key_token);
CREATE INDEX IF NOT EXISTS idx_device_activations_license ON device_activations(license_id);
CREATE INDEX IF NOT EXISTS idx_device_activations_fp ON device_activations(device_fingerprint);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs(actor_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_support_tickets_user ON support_tickets(user_id);
CREATE INDEX IF NOT EXISTS idx_analytics_events_created ON analytics_events(created_at);

-- Drop and recreate views to ensure updated column definitions
DROP VIEW IF EXISTS v_active_licenses_overview;
DROP VIEW IF EXISTS v_customer_summary;

-- Operational View: Active Licenses with Seat Usage
CREATE VIEW v_active_licenses_overview AS
SELECT 
    l.license_id,
    l.user_id,
    u.email AS customer_email,
    u.full_name AS customer_name,
    l.edition_code,
    p.display_name AS plan_name,
    l.license_key_token,
    l.status AS license_status,
    l.subscription_status,
    l.max_devices,
    COUNT(d.activation_id) AS active_device_count,
    MAX(0, l.max_devices - COUNT(d.activation_id)) AS remaining_seats,
    l.expires_at_ts,
    l.issued_at
FROM licenses l
LEFT JOIN users u ON l.user_id = u.user_id
LEFT JOIN pricing_plans p ON l.edition_code = p.edition_code
LEFT JOIN device_activations d ON l.license_id = d.license_id AND d.status = 'ACTIVE'
GROUP BY l.license_id;

-- Operational View: Customer Activity Summary
CREATE VIEW v_customer_summary AS
SELECT 
    u.user_id,
    u.email,
    u.full_name,
    u.role,
    u.is_active,
    COUNT(DISTINCT l.license_id) AS total_licenses,
    COUNT(DISTINCT d.activation_id) AS total_active_devices,
    COUNT(DISTINCT t.ticket_id) AS total_tickets,
    u.created_at
FROM users u
LEFT JOIN licenses l ON u.user_id = l.user_id
LEFT JOIN device_activations d ON l.license_id = d.license_id AND d.status = 'ACTIVE'
LEFT JOIN support_tickets t ON u.user_id = t.user_id
GROUP BY u.user_id;
