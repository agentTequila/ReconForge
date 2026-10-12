"""Active domain reconnaissance modules (opt-in via --active profile)."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

import requests

from reconforge.core.context import ScanContext
from reconforge.core.registry import register_module
from reconforge.core.target import Target

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993,
    995, 1433, 1521, 1723, 2049, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443,
    8888, 9000, 9090, 9200, 11211, 27017,
]

COMMON_DIRS = [
    "admin", "administrator", "login", "wp-admin", "dashboard", "cpanel", "backup",
    "backups", "old", "test", "dev", "staging", "api", "config", "uploads", "images",
    "includes", "phpmyadmin", "mysql", "database", "db", "private", "secret",
    "hidden", "temp", "tmp", "files", "download", "console", "metrics", "actuator",
    "swagger", "graphql", ".git", ".env", "server-status",
]

SENSITIVE_HINTS = ("admin", "config", "backup", "private", "secret", "console",
                   "actuator", "swagger", "env", "git")


@register_module(
    id="domain.ports",
    target_kinds=["domain"],
    profile="active",
    description="TCP port scan of common service ports",
)
def port_scan(target: Target, ctx: ScanContext):
    ip = socket.gethostbyname(target.value)
    open_ports: list[int] = []

    def probe(port: int) -> int | None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                if sock.connect_ex((ip, port)) == 0:
                    return port
        except OSError:
            pass
        return None

    with ThreadPoolExecutor(max_workers=50) as pool:
        for result in pool.map(probe, COMMON_PORTS):
            if result:
                open_ports.append(result)

    ctx.options["open_ports"] = sorted(open_ports)
    findings = []
    if len(open_ports) > 5:
        findings.append(f"{len(open_ports)} open ports on {ip} - verify each is required")
    if 3389 in open_ports:
        findings.append("RDP (3389) exposed - brute-force surface")
    if 22 in open_ports:
        findings.append("SSH (22) exposed - ensure key-only auth")
    return {"ip": ip, "open_ports": sorted(open_ports)}, findings


@register_module(
    id="domain.services",
    target_kinds=["domain"],
    profile="active",
    description="Banner grabbing on ports found by domain.ports",
)
def service_detection(target: Target, ctx: ScanContext):
    open_ports = ctx.options.get("open_ports") or []
    if not open_ports:
        return {"services": {}}, []
    ip = socket.gethostbyname(target.value)
    services: dict[str, str] = {}

    def grab(port: int) -> tuple[int, str]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(4)
                sock.connect((ip, port))
                try:
                    if port in (80, 8000, 8080, 8888, 8000):
                        sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " +
                                     target.value.encode() + b"\r\n\r\n")
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                except OSError:
                    banner = ""
                return port, banner[:200] or f"(no banner) open/{port}"
        except OSError as exc:
            return port, f"error: {exc}"

    with ThreadPoolExecutor(max_workers=20) as pool:
        for port, banner in pool.map(grab, open_ports):
            services[str(port)] = banner
    return {"services": services}, []


@register_module(
    id="domain.directories",
    target_kinds=["domain"],
    profile="active",
    description="Common directory/content discovery on the web server",
)
def directory_bruteforce(target: Target, ctx: ScanContext):
    found: list[dict] = []

    def probe(path: str) -> dict | None:
        for scheme in ("https", "http"):
            try:
                resp = ctx.http(
                    "GET", f"{scheme}://{target.value}/{path}",
                    timeout=5, allow_redirects=False,
                )
                if resp.status_code in (200, 301, 302, 401, 403):
                    return {"path": path, "status": resp.status_code,
                            "url": f"{scheme}://{target.value}/{path}"}
                break
            except requests.RequestException:
                continue
        return None

    from reconforge.modules.common import chunked_map

    for result in chunked_map(probe, COMMON_DIRS, max_workers=15):
        if result:
            found.append(result)

    sensitive = [d for d in found if any(h in d["path"] for h in SENSITIVE_HINTS)]
    findings = []
    if sensitive:
        findings.append(
            "Sensitive paths responding: " + ", ".join(f"/{d['path']}" for d in sensitive[:5])
        )
    return {"found": found, "sensitive": sensitive}, findings


@register_module(
    id="domain.http_methods",
    target_kinds=["domain"],
    profile="active",
    description="Allowed/dangerous HTTP methods (OPTIONS probe)",
)
def http_methods(target: Target, ctx: ScanContext):
    resp = ctx.http("OPTIONS", f"https://{target.value}", timeout=10)
    allow = resp.headers.get("Allow") or resp.headers.get("Public") or "Not specified"
    dangerous = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT")
                 if m in allow.upper()]
    findings = []
    if dangerous:
        findings.append(f"Dangerous HTTP methods allowed: {', '.join(dangerous)}")
    return {"allow": allow, "dangerous": dangerous}, findings
