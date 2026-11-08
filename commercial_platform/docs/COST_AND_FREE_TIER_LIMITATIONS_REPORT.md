# NexoraAI V14.2 Cloud Service — Cost & Free-Tier Limitations Report

## Executive Summary
This report analyzes the financial budget, resource utilization, free-tier cloud limits, and architectural mitigations for the production deployment of the **NexoraAI V14.2 Commercial Licensing & Distribution Service**.

### Zero-Budget Bottom Line
- **Monthly Cloud Operating Cost:** **$0.00 / month** (100% Free-Tier Architecture)
- **Local Server Obligation:** **$0.00** (Personal computer is never used as a server)
- **GPU Cost:** **$0.00** (Zero cloud GPUs required; desktop client performs local CPU neural inference)
- **Installer Bandwidth Cost:** **$0.00** (Cloudflare R2 provides 0-egress object storage)

---

## 1. Cloud Resource Profile & Empirical Footprint

Measurements taken during the live execution of the Commercial Platform WSGI Server (`wsgi_production_server.py`) and E2E test suites:

| Metric | Measured Value | Allocation Budget | Utilization Ratio |
| :--- | :--- | :--- | :--- |
| **Process Resident Memory (VmRSS)** | **42.15 MB** | 512 MB (Render Free) | **8.23%** (91.8% Headroom) |
| **Idle CPU Utilization** | **0.02%** | 0.1 vCPU (Shared) | Negligible |
| **Peak Inference Load on Cloud** | **0.00 MB** | 0 MB | **0%** (Inference is 100% Client-Side) |
| **Initial Database Size (`schema.sql`)** | **156 KB** | 1,000 MB (Fly.io Vol) | **0.015%** |
| **Desktop Installer Artifact** | **123.4 MB** | 10,000 MB (Cloudflare R2) | **1.23%** |

---

## 2. Free-Tier Provider Limits & Architectural Mitigations

### 2.1 Render Free Web Service
- **Allocated Free Resources:** 512 MB RAM, 0.1 shared vCPU, 100 GB/month egress bandwidth.
- **Limitation — Idle Spin-Down:** Render free web services spin down after 15 minutes of inactivity. When a customer or desktop app makes a request after spin-down, the container cold-starts, causing a **30 to 50-second latency** on the initial HTTP response.
- **Architectural Mitigation:**
  1. Desktop client implements a 60-second connection timeout and cached local offline leases (30-day validity) so desktop users are never blocked by cold starts.
  2. A free external ping service (such as [UptimeRobot](https://uptimerobot.com) or GitHub Actions cron) pinging `GET /api/v1/health` every 10 minutes keeps the Render instance warm during active business hours at zero cost.
- **Limitation — Ephemeral Storage:** Free container storage is wiped on redeployments or container restarts.
- **Architectural Mitigation:** Database backups are automatically created via `POST /api/v1/admin/database/backup` and can be pushed to Cloudflare R2 object storage, or Fly.io can be selected when persistent local volumes are required.

### 2.2 Fly.io Free Allowance
- **Allocated Free Resources:** Up to 3 shared-cpu-1x VMs (256 MB RAM each) and 3 GB persistent storage volumes.
- **Evaluation:** Fly.io provides persistent NVMe disk mounts (`[[mounts]] destination = "/data"`), meaning SQLite databases survive restarts and updates without external database services.
- **Limitation:** 256 MB RAM limit is tight for standard Node.js/Java apps, but the Nexora pure-Python cloud service consumes only 42 MB, leaving over **214 MB of free RAM headroom**.

### 2.3 Cloudflare R2 vs AWS S3 (Installer Distribution)
- **The Problem:** The full standalone Native Desktop installer tarball is **123.4 MB**. If 1,000 customers download the desktop app directly from a container host, the bandwidth egress is:
  $$\text{Egress} = 1,000 \times 123.4\text{ MB} \approx 123.4\text{ GB}$$
  This would exceed the 100 GB monthly free limit on Render or Fly.io, incurring surprise overage charges or service throttling.
- **The Solution — Cloudflare R2:**
  - Storage: 10 GB free forever.
  - Egress Bandwidth: **$0.00 / GB (Always Free, zero egress fees)**.
  - Pure-Python SigV4 Presigned URLs: The cloud gateway signs a temporary 15-minute download URL and redirects the client with an HTTP 302. The client downloads directly from Cloudflare's high-speed global CDN at zero cost to the operator.

---

## 3. Scaling Milestones & Future Cost Projection

| Stage | Active Customers | Monthly Infrastructure Cost | Recommended Hosting Architecture |
| :--- | :--- | :--- | :--- |
| **Phase 1: Launch & Beta** | 0 – 1,000 users | **$0.00 / month** | Render Free / Fly.io + Cloudflare R2 (100% Free Tier) |
| **Phase 2: Commercial Traction** | 1,000 – 10,000 users | **$7.00 / month** | Render Starter ($7/mo, no spin-down, 512 MB RAM) + Cloudflare R2 |
| **Phase 3: Multi-Seat Growth** | 10,000 – 50,000 users | **$25.00 / month** | Dedicated Linux VPS (Hetzner / DigitalOcean 4GB RAM) + Caddy TLS 1.3 |
| **Phase 4: Global Enterprise** | 50,000+ users | **$75.00 / month** | Managed PostgreSQL (Neon / Supabase) + Multi-Region Containers |

---

## 4. Payment Safety & Financial Protection Guarantees

1. **Merchant Onboarding Gate:**
   `NEXORA_ENABLE_LIVE_PAYMENTS=false` is enforced at the server routing level. Until merchant onboarding with Stripe or Lemon Squeezy is formally executed by an authorized adult, no customer checkout can occur and zero transactions can be initiated.
2. **Zero Raw Credit Card Exposure:**
   The cloud gateway rejects any payload containing raw card data with HTTP 403. Payment data is never transmitted to or processed by the server, eliminating PCI-DSS compliance overhead.
3. **Webhook Idempotency:**
   Inbound merchant events are cryptographically authenticated using HMAC-SHA256 and tracked by `event_id` in SQLite, preventing duplicate order processing or duplicate license issuance during network retries.
