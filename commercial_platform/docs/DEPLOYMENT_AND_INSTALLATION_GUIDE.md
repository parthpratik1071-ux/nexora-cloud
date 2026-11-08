# NexoraAI V14.2 Commercial Platform — Deployment & Installation Guide

## 1. Required Production Environment Variables
Never hardcode secrets in source files. Configure the following environment variables on your production server:
```bash
export NEXORA_LICENSE_PRIVATE_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export NEXORA_SESSION_HMAC_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export NEXORA_DOWNLOAD_HMAC_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export NEXORA_PAYMENT_WEBHOOK_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
# Keep false until legal entity & payment provider onboarding are completed:
export NEXORA_ENABLE_LIVE_PAYMENTS="false"
```

## 2. Running the Security & Verification Suites
```bash
# 1. Run the 16-test Commercial Security, Penetration, Licensing & IP Quarantine Suite
python3 commercial_platform/tests/run_commercial_security_and_ip_suite.py

# 2. Run the Native Desktop Application Self-Test (Offline Lease + V14.2 Native Inference + SQLite History)
python3 commercial_platform/desktop/nexora_desktop_app.py --self-test

# 3. Verify the Frozen Native V14.2 Inference Engine Directly
python3 engine_v14_1/inference/native_v14_2_cli.py --identity
```

## 3. Pre-Launch Mandatory Checklist
1. **IP Audit:** Complete legal review of `commercial_platform/docs/IP_COMPLIANCE_REPORT.md` and `commercial_platform/legal/LEGAL_DRAFTS_BUNDLE.md`. Keep the Qwen-compatible LoRA adapter quarantined (`commercial_distribution_allowed = 0`) until all Apache-2.0 and dataset obligations are cleared.
2. **Legal & Payment Onboarding:** Complete merchant registration with an eligible adult/legal business representative before setting `NEXORA_ENABLE_LIVE_PAYMENTS="true"`.
3. **HTTPS Termination:** Deploy behind an HTTPS reverse proxy (Nginx / Caddy / Cloudflare TLS 1.3) with the built-in HSTS and CSP headers enabled.
