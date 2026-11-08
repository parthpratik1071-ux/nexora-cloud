# NexoraAI V14.2 — Commercial Legal Documentation Drafts

> **[DRAFT — REQUIRES QUALIFIED LEGAL REVIEW BEFORE COMMERCIAL USE]**
> These documents are engineering and commercial policy drafts prepared for **NexoraAI V14.2** (Owner: **Pratik Parth / Authorized Legal Entity**). They do not constitute formal legal advice and must be reviewed and finalized by qualified legal counsel in your jurisdiction prior to accepting commercial payments or executing customer contracts.

---

## DOCUMENT 1: PROPRIETARY SOFTWARE END-USER LICENSE AGREEMENT (EULA) [DRAFT]

1. **Grant of License:** Subject to timely payment of applicable fees and continuous compliance with this Agreement, Licensor (**Pratik Parth / Authorized Entity**) grants Licensee a non-exclusive, non-transferable, revocable license to install and execute **NexoraAI V14.2 (Native Standalone Edition)** strictly up to the maximum number of registered devices and seats specified by Licensee's purchased Edition (**Personal**, **Professional**, **Developer**, **Enterprise**, or **API Edition**).
2. **Edition-Specific Restrictions:**
   - **Personal Edition:** Permitted solely for personal, non-commercial evaluation and individual productivity on one (1) registered device.
   - **Professional & Developer Editions:** Permitted for internal professional and commercial software development up to the licensed device limit. Redistribution of the underlying NexoraAI neural checkpoints (`model.safetensors`) or licensing bypass tools is strictly prohibited.
   - **Enterprise & API Editions:** Governed by the seat count, rate limits, and organizational schedules recorded in the applicable Order Form.
3. **Intellectual Property & Open-Source Separation:** Licensor retains title to the proprietary NexoraAI commercial application platform, licensing system, and first-party Native V14.2 neural architecture. Third-party open-source libraries (including NumPy, SciPy, SymPy, Python, and optional Qt/PySide6 libraries) remain the property of their respective copyright holders and are licensed under their applicable open-source licenses set forth in Section 6 (Third-Party Notices).
4. **Prohibition on Reverse Engineering of Licensing Controls:** Except to the extent expressly permitted by applicable law or LGPL-3.0 (solely with respect to dynamically linked LGPL libraries), Licensee shall not forge, tamper with, or redistribute cryptographic license tokens (`NXRA-V142-...`), offline activation leases, or single-use download tokens.
5. **High-Risk & Verification Disclaimer:** NexoraAI V14.2 is a compact (`15.68M`-parameter) local neuro-symbolic system. While algebraic and code outputs marked `SYMBOLICALLY_VERIFIED` or `Code verified` have been checked by local SymPy or sandbox execution, natural-language outputs are probabilistic and must not be relied upon for medical, legal, aviation, nuclear, or life-critical decisions.

---

## DOCUMENT 2: TERMS OF SERVICE (ToS) [DRAFT]

1. **Eligibility & Contracting Entity:** Commercial purchases and enterprise agreements may only be executed by individuals of legal majority (`18+` or applicable age of majority) or authorized corporate representatives.
2. **Account Security & Device Registration:** Customers are responsible for safeguarding account credentials and API keys (`nxra_live_...`). Accounts are protected by PBKDF2-HMAC-SHA256 hashing and automatic brute-force lockouts.
3. **Configurable Pricing & Taxes:** Pricing plans for each Edition are configured by the Administrator and displayed prior to checkout. Payment processing remains disabled until formal merchant onboarding and tax compliance registration are active.
4. **License Revocation for Abuse:** Licensor reserves the right to suspend or revoke licenses in response to confirmed payment chargebacks, fraudulent webhook spoofing, or distribution of leaked activation credentials.

---

## DOCUMENT 3: PRIVACY POLICY [DRAFT]

1. **Zero Collection of Private Chat Prompts & Local Inference Data:** NexoraAI V14.2 Desktop executes neural inference locally on your hardware. **By design and technical enforcement (`FORBIDDEN_PRIVACY_KEYS` in `analytics_service.py`), NexoraAI NEVER collects, transmits, or stores your private chat conversations, prompts, or local Semantic Memory documents on our servers.**
2. **Account & Licensing Metadata Collected:** When you register an account, activate a device, or request a software download, we store only:
   - Account contact details (`email`, `full_name`, `organization`) and salted PBKDF2 password hashes (`600,000` iterations).
   - License activation metadata (`license_id`, `device_fingerprint` hash, `device_name`, `os_platform`, `app_version`, and activation timestamps).
   - Order and invoice identifiers verified via external payment webhooks (we **never** receive or store raw credit card numbers or CVV codes).
3. **Opt-In Operational Telemetry:** Anonymous aggregate counts of downloads, activations, and installation errors may be toggled on or off by the user at any time (`analytics_opt_in`).

---

## DOCUMENT 4: ACCEPTABLE USE POLICY (AUP) [DRAFT]

Licensees and API users may not use NexoraAI V14.2 to:
1. Generate or execute malicious code, exploit payloads, or denial-of-service scripts outside the restricted local verification sandbox.
2. Attempt to bypass authentication, brute-force license keys, spoof payment webhooks (`X-Webhook-Signature`), or share single-user activation leases across unauthorized machines.
3. Misrepresent outputs of the compact `15.68M`-parameter local model as human professional advice (medical, legal, or financial).

---

## DOCUMENT 5: REFUND & CANCELLATION POLICY [DRAFT]

1. **Refund Processing & Automatic License Revocation:** When an authorized refund is processed through the payment provider (`payment.refunded` webhook), the associated invoice is marked `REFUNDED` and the corresponding software license (`license_id`) and all registered device activations are automatically transitioned to `REVOKED` / `DEACTIVATED`.
2. **Subscription Cancellation:** Customers may cancel recurring subscriptions via the Customer Dashboard; access continues until the end of the paid billing period (`expires_at_ts`).

---

## DOCUMENT 6: THIRD-PARTY OPEN-SOURCE NOTICES

NexoraAI V14.2 incorporates or interacts with the following open-source components, which are **not** owned by NexoraAI:
- **NumPy (`2.1.3`), SciPy (`1.15.2`), SymPy (`1.13.3`):** Copyright (c) NumPy, SciPy, and SymPy Developers. Licensed under the **BSD 3-Clause License**.
- **PyYAML (`6.0`), FastAPI (`0.92.0`), Pydantic (`1.10.4`):** Licensed under the **MIT License**.
- **Python Runtime (`3.11+`) & Tkinter:** Copyright (c) Python Software Foundation. Licensed under the **PSF License Version 2**.
- **Optional Qwen2.5-0.5B-Instruct Compatibility Layer (Quarantined):** `Qwen/Qwen2.5-0.5B-Instruct` is developed by the Qwen Team / Alibaba Cloud and licensed under the **Apache License, Version 2.0**. NexoraAI claims zero ownership over Qwen base weights or tokenizer specifications.
