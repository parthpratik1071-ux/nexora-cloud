# NexoraAI V14.2 Cloud Service — Zero-Budget Cloud Deployment Guide

## Core Principles & Budget Boundaries
1. **Never Use Your Personal PC/Laptop as a Production Server:** Production traffic must be hosted on dedicated cloud infrastructure to prevent downtime, domestic IP exposure, ISP terms violations, and thermal stress on personal hardware.
2. **Zero Paid GPU Usage:** The cloud service handles authentication, commercial licensing, device seat enforcement, and installer distribution. Local inference is executed entirely on the customer's machine using CPU/RAM. The cloud service has zero heavy machine learning dependencies (no PyTorch, CUDA, or transformers required), maintaining an ultra-lightweight memory footprint of under **45 MB RAM**.
3. **Zero Unexpected Subscriptions:** Designed exclusively around generous free-tier cloud platforms (Render, Fly.io, Cloudflare Pages, Cloudflare R2, and Railway).
4. **Frozen Model & Checkpoint Integrity:** The Native V14.2 neural weights (`62,741,608` bytes, SHA-256: `d285ab0e4e24916f27a7d7ec4b846c6a5bbc00e6f92d455f02083f851c073e56`) and inference engine are preserved byte-for-byte.

---

## Architecture Diagram (Production Cloud & Desktop Product)

```text
+-----------------------------------------------------------------------------------+
|                           CUSTOMER CLIENT ENVIRONMENT                             |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  |                 NexoraAI V14.2 Native Desktop Application                   |  |
|  |  - 100% Local Neural Inference (15.68M params, 39 FP32 tensors, CPU)       |  |
|  |  - Local SymPy Symbolic Solver Verification (Deterministic Math)            |  |
|  |  - Semantic Memory 2.2 Vector Store & Local History (SQLite)                |  |
|  |  - Public Digest Offline Lease Verification (Zero Client Private Keys)      |  |
|  +-----------------------------------------------------------------------------+  |
+--------------------------------------|--------------------------------------------+
                                       |
                   HTTPS TLS 1.3       | Periodic Heartbeat &
                (Encrypted API Sockets)| Single-Use Downloads
                                       v
+-----------------------------------------------------------------------------------+
|                        PRODUCTION ZERO-BUDGET CLOUD TIER                          |
|                                                                                   |
|  +----------------------------------+    +-------------------------------------+  |
|  |  Cloudflare Edge Network / DNS   |    |    Cloudflare R2 Object Storage     |  |
|  |  - Free TLS 1.3 Termination      |    |  - 10 GB Free Storage               |  |
|  |  - DDoS Mitigation & HSTS        |    |  - $0.00 Free Egress Bandwidth      |  |
|  |  - Cloudflare Pages Web Mirror   |    |  - Private Desktop Installers       |  |
|  +-----------------|----------------+    +------------------^------------------+  |
|                    |                                        |                     |
|                    v Reverse Proxy                          | 15-Min Signed       |
|  +----------------------------------+                       | SigV4 Redirect      |
|  |   Free Container Cloud Host      |                       |                     |
|  |   (Render / Fly.io / Railway)    |-----------------------+                     |
|  |                                  |                                             |
|  |  - Commercial Gateway (Python 3) |                                             |
|  |  - Rate Limiter (60 req/min/IP)  |                                             |
|  |  - PBKDF2-600k Authentication    |                                             |
|  |  - SQLite Database (WAL Mode)    |                                             |
|  |  - Admin RBAC & Audit Logger     |                                             |
|  |  - Memory Footprint: ~42 MB RAM  |                                             |
|  +----------------------------------+                                             |
+-----------------------------------------------------------------------------------+
```

---

## Deployment Option A: Render Free Web Service (Recommended)

Render provides a free web service tier with 512 MB RAM, free HTTPS certificates, and Git auto-deployments.

### Step 1: Push Repository to GitHub or GitLab
Ensure your commercial platform code is committed to a private or public Git repository.

### Step 2: Create Web Service on Render
1. Log in to your Render dashboard at [https://dashboard.render.com](https://dashboard.render.com).
2. Click **New +** > **Web Service**.
3. Connect your repository.
4. Render will automatically detect `render.yaml`, or you can configure manually:
   - **Environment:** `Python 3`
   - **Build Command:** `pip install --upgrade pip`
   - **Start Command:** `python3 commercial_platform/api/wsgi_production_server.py --host 0.0.0.0 --port $PORT`
   - **Instance Type:** `Free` (0.1 CPU, 512 MB RAM)

### Step 3: Configure Environment Variables
In the Render dashboard under **Environment Variables**, configure:
```ini
HOST=0.0.0.0
PORT=10000
PYTHONUNBUFFERED=1
NEXORA_STORAGE_BACKEND=local
NEXORA_ENABLE_LIVE_PAYMENTS=false
NEXORA_RATE_LIMIT_PER_MINUTE=60
NEXORA_SESSION_HMAC_SECRET=<generate_via_secrets_token_hex>
NEXORA_LICENSE_PRIVATE_KEY=<generate_via_secrets_token_hex>
NEXORA_DOWNLOAD_HMAC_SECRET=<generate_via_secrets_token_hex>
NEXORA_PAYMENT_WEBHOOK_SECRET=<generate_via_secrets_token_hex>
NEXORA_ADMIN_INITIAL_EMAIL=admin@nexora.local
NEXORA_ADMIN_INITIAL_PASSWORD=<strong_admin_password>
```

### Step 4: Verification
Render assigns a public HTTPS URL (e.g., `https://nexora-cloud-licensing.onrender.com`).
Verify health:
```bash
curl -I https://nexora-cloud-licensing.onrender.com/api/v1/health
```

---

## Deployment Option B: Fly.io Free VM (With Persistent Volume)

Fly.io provides free shared-CPU VMs with up to 3 GB persistent disk storage in their free allowance.

### Step 1: Install flyctl CLI
```bash
curl -L https://fly.io/install.sh | sh
```

### Step 2: Create Fly App and Storage Volume
```bash
fly auth login
fly apps create nexora-cloud-licensing
fly volumes create nexora_data --size 1 --region iad
```

### Step 3: Set Production Secrets
```bash
fly secrets set \
  NEXORA_SESSION_HMAC_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))") \
  NEXORA_LICENSE_PRIVATE_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))") \
  NEXORA_DOWNLOAD_HMAC_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))") \
  NEXORA_PAYMENT_WEBHOOK_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))") \
  NEXORA_ADMIN_INITIAL_PASSWORD="YourStrongAdminPassword2026!"
```

### Step 4: Deploy
```bash
fly deploy --config commercial_platform/fly.toml
```

---

## Deployment Option C: Cloudflare R2 for Zero-Egress Installer Storage

Desktop installers are approximately **123 MB**. Free cloud container tiers (Render, Fly.io, Railway) have monthly egress bandwidth quotas (e.g. 100 GB). Serving downloads directly through container bandwidth would exhaust limits after 800 downloads.

**Cloudflare R2 provides 10 GB of free object storage with $0.00 egress bandwidth fees forever.**

### Step 1: Create R2 Bucket
1. Log in to Cloudflare Dashboard > **R2**.
2. Click **Create Bucket** and name it `nexora-commercial-releases`.

### Step 2: Upload Installers to R2
Upload `NexoraAI_V14_2_Native_Desktop_Installer.tar.gz` to the root of the bucket.

### Step 3: Generate R2 API Tokens
In Cloudflare R2 > **Manage R2 API Tokens**, create an API token with **Object Read & Write** permissions. Note:
- Account ID
- Access Key ID
- Secret Access Key

### Step 4: Configure Gateway for S3 Presigned URLs
Set these environment variables on your cloud container:
```ini
NEXORA_STORAGE_BACKEND=s3_presigned
NEXORA_S3_ENDPOINT_URL=https://<your_account_id>.r2.cloudflarestorage.com
NEXORA_S3_BUCKET=nexora-commercial-releases
NEXORA_S3_REGION=auto
NEXORA_S3_ACCESS_KEY_ID=<your_r2_access_key_id>
NEXORA_S3_SECRET_ACCESS_KEY=<your_r2_secret_access_key>
```
*How It Works:* When an authorized customer requests a download, the server verifies their license entitlement, consumes their single-use token, generates an AWS SigV4 presigned GET URL valid for 15 minutes, and issues an HTTP 302 redirect. The customer downloads directly from Cloudflare R2 at maximum speed with zero container bandwidth consumed and zero credentials leaked.

---

## Deployment Option D: Self-Hosted Linux VPS with Caddy

For users deploying to an existing Linux VPS (Ubuntu/Debian) with systemd.

### Step 1: Install Caddy (Automatic HTTPS)
```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install caddy
```

### Step 2: Configure Systemd Service
```bash
sudo cp commercial_platform/config/systemd_nexora_commercial.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now systemd_nexora_commercial.service
```

### Step 3: Configure Caddy Reverse Proxy
```bash
sudo cp commercial_platform/config/Caddyfile /etc/caddy/Caddyfile
sudo systemctl restart caddy
```

---

## Automated Database Backup & Disaster Recovery

### Creating a Hot Database Backup
Admins can trigger backups via the Web Admin Console or via REST API:
```bash
curl -X POST https://nexora.example.com/api/v1/admin/database/backup \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"tag": "weekly_scheduled"}'
```
Backups are saved to `commercial_platform/backups/` and record their SHA-256 checksum in `backup_manifest.json`.

### Restoring from a Backup
To restore in disaster recovery mode:
```bash
python3 -c "
import sys; sys.path.insert(0, '.');
from commercial_platform.database.db_manager import DatabaseManager
db = DatabaseManager()
manifest = db.restore_from_backup('commercial_platform/backups/backup_weekly_scheduled_*.sqlite3')
print('Restored successfully:', manifest)
"
```

---

## Post-Deployment Verification Checklist

Execute these checks after every deployment:

- [ ] **1. Public Health Check:** `GET /api/v1/health` returns `HTTP 200` with `status: HEALTHY`.
- [ ] **2. Model Checkpoint Integrity:** `native_v14_2_checkpoint_present` is `true`.
- [ ] **3. Security Headers:** Check response headers include `Strict-Transport-Security` and `X-Frame-Options: DENY`.
- [ ] **4. Rate Limiting:** Exceeding 60 requests/minute returns `HTTP 429`.
- [ ] **5. RBAC Isolation:** Attempting to access `/api/v1/admin/monitoring` without admin token returns `HTTP 403 Forbidden`.
- [ ] **6. IP Quarantine Enforcement:** Authorizing quarantined Qwen LoRA returns `HTTP 403 Forbidden`.
- [ ] **7. Payment Safety:** `POST /api/v1/payments/checkout` returns `HTTP 503` (checkout disabled by default).
- [ ] **8. RAM Usage:** Monitoring probe confirms RSS under 50 MB RAM.
