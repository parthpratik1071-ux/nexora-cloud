#!/usr/bin/env python3
"""
NexoraAI V14.2 Commercial Platform — Live Production WSGI / HTTP / TLS Server
(`commercial_platform/api/wsgi_production_server.py`)
-----------------------------------------------------------------------------
Deploys the real NexoraAI V14.2 Commercial Platform over a live TCP/HTTP (and optional
TLS 1.3 `ssl.SSLContext`) socket using Python's `wsgiref.simple_server` / `http.server`:
  - Serves the live commercial website (`GET /` -> `commercial_platform/web/index.html`)
  - Serves all REST API endpoints (`/api/v1/public/*`, `/api/v1/auth/*`, `/api/v1/licenses/*`,
    `/api/v1/customer/*`, `/api/v1/downloads/*`, `/api/v1/payments/*`, `/api/v1/admin/*`)
  - Serves real authenticated binary file downloads (`GET /api/v1/downloads/stream?token=<signed_token>`)
    with `Content-Disposition: attachment`, `X-Content-SHA256`, and single-use token consumption
  - Serves real-time health & monitoring probes (`GET /api/v1/health`, `GET /api/v1/admin/monitoring`)
  - Enforces security headers (`Strict-Transport-Security`, `X-Frame-Options: DENY`,
    `X-Content-Type-Options: nosniff`), rate limiting, and error monitoring.
"""
import argparse
import hashlib
import json
import os
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

API_DIR = Path(__file__).resolve().parent
COMMERCIAL_ROOT = API_DIR.parent
PROJECT_ROOT = COMMERCIAL_ROOT.parent
sys.path.insert(0, str(PROJECT_ROOT))

from commercial_platform.api.app_server import CommercialPlatformAPIServer
from commercial_platform.services.monitoring_and_tls import ProductionMonitoringService
from commercial_platform.services.auth_service import SecurityError, AuthorizationError
from commercial_platform.services.distribution_service import DistributionError


class ProductionCommercialGateway:
    def __init__(self, db_path: Path | None = None):
        self.api = CommercialPlatformAPIServer(db_path=db_path)
        self.monitoring = ProductionMonitoringService(self.api.db, PROJECT_ROOT)
        self.web_index_path = COMMERCIAL_ROOT / "web/index.html"


def make_http_handler(gateway: ProductionCommercialGateway):
    class NexoraProductionHTTPHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format_str, *args):
            # Suppress noisy stdout access logs during automated tests unless NEXORA_VERBOSE_HTTP=1
            if os.environ.get("NEXORA_VERBOSE_HTTP") == "1":
                super().log_message(format_str, *args)

        def _send_json(self, status_code: int, payload: dict, extra_headers: dict | None = None):
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            for hk, hv in gateway.api.SECURITY_HEADERS.items():
                self.send_header(hk, hv)
            if extra_headers:
                for hk, hv in extra_headers.items():
                    self.send_header(hk, hv)
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            parsed = urlparse(self.path)
            path = parsed.path
            qs = parse_qs(parsed.query)
            client_ip = self.client_address[0] if self.client_address else "127.0.0.1"

            try:
                # 1. Serve Live Commercial Website at `/` or `/index.html`
                if path in ("/", "/index.html"):
                    html_bytes = gateway.web_index_path.read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(html_bytes)))
                    for hk, hv in gateway.api.SECURITY_HEADERS.items():
                        self.send_header(hk, hv)
                    self.end_headers()
                    self.wfile.write(html_bytes)
                    return

                # 2. Health Probe Endpoint
                if path == "/api/v1/health":
                    health = gateway.monitoring.check_system_health()
                    self._send_json(200 if health["status"] == "HEALTHY" else 503, {"data": health})
                    return

                # 3. Admin Monitoring Endpoint
                if path == "/api/v1/admin/monitoring":
                    auth_hdr = self.headers.get("Authorization", "")
                    token = auth_hdr.replace("Bearer ", "")
                    _ = gateway.api.auth.verify_session(token, required_role="admin", ip_address=client_ip)
                    rep = gateway.monitoring.get_admin_monitoring_report()
                    self._send_json(200, {"data": rep})
                    return

                # 4. Authenticated Binary Stream Download Endpoint (`GET /api/v1/downloads/stream?token=...`)
                if path == "/api/v1/downloads/stream":
                    dl_token = (qs.get("token") or [""])[0]
                    stream_meta = gateway.api.distribution.consume_download_token(dl_token, ip_address=client_ip)
                    gateway.api.analytics.record_event("DOWNLOAD", stream_meta["version"], None, None, {"release_id": stream_meta["release_id"]})

                    # If presigned URL is available (e.g. Cloudflare R2 / S3), issue 302 redirect
                    if stream_meta.get("presigned_download_url"):
                        self.send_response(302)
                        self.send_header("Location", stream_meta["presigned_download_url"])
                        self.send_header("X-Artifact-SHA256", stream_meta["sha256_checksum"])
                        self.send_header("X-Package-Signature", stream_meta["package_signature"])
                        for hk, hv in gateway.api.SECURITY_HEADERS.items():
                            self.send_header(hk, hv)
                        self.end_headers()
                        return

                    file_path = PROJECT_ROOT / stream_meta["artifact_path"]
                    if not file_path.exists():
                        self._send_json(404, {"error": "Artifact file missing on server."})
                        return

                    # Support optional `head_bytes` query param for fast streaming verification without reading 62MB in unit tests
                    head_bytes = int((qs.get("head_bytes") or ["0"])[0])
                    if head_bytes > 0:
                        with open(file_path, "rb") as f:
                            data_bytes = f.read(head_bytes)
                    else:
                        data_bytes = file_path.read_bytes()

                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Disposition", f'attachment; filename="{file_path.name}"')
                    self.send_header("Content-Length", str(len(data_bytes)))
                    self.send_header("X-Artifact-SHA256", stream_meta["sha256_checksum"])
                    self.send_header("X-Package-Signature", stream_meta["package_signature"])
                    for hk, hv in gateway.api.SECURITY_HEADERS.items():
                        self.send_header(hk, hv)
                    self.end_headers()
                    self.wfile.write(data_bytes)
                    return

                # 5. Dispatch standard GET API requests
                hdrs = {"Authorization": self.headers.get("Authorization", "")}
                query_payload = {k: v[0] if len(v) == 1 else v for k, v in qs.items()}
                resp = gateway.api.handle_request("GET", path, body=query_payload, headers=hdrs, ip_address=client_ip)
                code = resp.pop("status_code", 200)
                resp.pop("headers", None)
                self._send_json(code, resp)

            except AuthorizationError as exc:
                gateway.monitoring.record_error("WARNING", "HTTP_GET", "AuthorizationError", str(exc), path)
                self._send_json(403, {"error": str(exc)})
            except (SecurityError, DistributionError) as exc:
                gateway.monitoring.record_error("WARNING", "HTTP_GET", type(exc).__name__, str(exc), path)
                self._send_json(403, {"error": str(exc)})
            except Exception as exc:
                gateway.monitoring.record_error("ERROR", "HTTP_GET", type(exc).__name__, str(exc), path)
                self._send_json(500, {"error": "Internal Server Error"})

        def do_POST(self):
            parsed = urlparse(self.path)
            path = parsed.path
            client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
            try:
                content_len = int(self.headers.get("Content-Length", "0"))
                if content_len > 1024 * 1024:
                    self._send_json(413, {"error": "Payload Too Large (max 1 MB)"})
                    return
                raw_body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
                body = json.loads(raw_body) if raw_body.strip() else {}
                hdrs = {
                    "Authorization": self.headers.get("Authorization", ""),
                    "X-Webhook-Signature": self.headers.get("X-Webhook-Signature", ""),
                }
                resp = gateway.api.handle_request("POST", path, body=body, headers=hdrs, ip_address=client_ip)
                code = resp.pop("status_code", 200)
                resp.pop("headers", None)
                if code >= 400:
                    gateway.monitoring.record_error("WARNING", "HTTP_POST", f"HTTP_{code}", resp.get("error", ""), path)
                self._send_json(code, resp)
            except Exception as exc:
                gateway.monitoring.record_error("ERROR", "HTTP_POST", type(exc).__name__, str(exc), path)
                self._send_json(400, {"error": str(exc)})

    return NexoraProductionHTTPHandler


def write_production_tls_and_systemd_configs():
    cfg_dir = COMMERCIAL_ROOT / "config"
    cfg_dir.mkdir(parents=True, exist_ok=True)

    nginx_conf = """# NexoraAI V14.2 — Production HTTPS / TLS 1.3 Reverse Proxy Configuration (`nginx_tls13_production.conf`)
server {
    listen 80;
    server_name nexora.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name nexora.example.com;

    ssl_certificate     /etc/letsencrypt/live/nexora.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/nexora.example.com/privkey.pem;
    ssl_protocols       TLSv1.3 TLSv1.2;
    ssl_ciphers         ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    client_max_body_size 1M;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
"""
    (cfg_dir / "nginx_tls13_production.conf").write_text(nginx_conf, encoding="utf-8")

    caddyfile = """# NexoraAI V14.2 — Automatic Let's Encrypt HTTPS Configuration (`Caddyfile`)
nexora.example.com {
    encode zstd gzip
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Frame-Options "DENY"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "strict-origin-when-cross-origin"
        -Server
    }
    reverse_proxy 127.0.0.1:8080
}
"""
    (cfg_dir / "Caddyfile").write_text(caddyfile, encoding="utf-8")

    systemd_unit = """# NexoraAI V14.2 — Production Systemd Service (`systemd_nexora_commercial.service`)
[Unit]
Description=NexoraAI V14.2 Commercial Licensing, Distribution & Web Platform
After=network.target

[Service]
Type=simple
User=nexora
Group=nexora
WorkingDirectory=/opt/NexoraAI_V14_2_Commercial_Product
EnvironmentFile=/etc/nexora/production.env
ExecStart=/usr/bin/python3 commercial_platform/api/wsgi_production_server.py --host 127.0.0.1 --port 8080
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/NexoraAI_V14_2_Commercial_Product/commercial_platform/database /opt/NexoraAI_V14_2_Commercial_Product/commercial_platform/backups

[Install]
WantedBy=multi-user.target
"""
    (cfg_dir / "systemd_nexora_commercial.service").write_text(systemd_unit, encoding="utf-8")


def main():
    default_host = os.environ.get("HOST", "127.0.0.1")
    default_port = int(os.environ.get("PORT", "8080"))
    parser = argparse.ArgumentParser(description="NexoraAI V14.2 Live Production HTTP/HTTPS Server")
    parser.add_argument("--host", type=str, default=default_host, help="Host/IP to bind (default: $HOST or 127.0.0.1)")
    parser.add_argument("--port", type=int, default=default_port, help="Port to bind (default: $PORT or 8080)")
    parser.add_argument("--tls-cert", type=str, default=None, help="Optional path to PEM certificate for native HTTPS")
    parser.add_argument("--tls-key", type=str, default=None, help="Optional path to PEM private key for native HTTPS")
    args = parser.parse_args()

    write_production_tls_and_systemd_configs()
    gateway = ProductionCommercialGateway()
    handler_cls = make_http_handler(gateway)
    httpd = ThreadingHTTPServer((args.host, args.port), handler_cls)

    if args.tls_cert and args.tls_key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=args.tls_cert, keyfile=args.tls_key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        proto = "HTTPS"
    else:
        proto = "HTTP"

    print(f"NexoraAI V14.2 Commercial Production Server listening on {proto}://{args.host}:{args.port}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
