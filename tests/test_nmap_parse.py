"""nmap output parser tests (no nmap binary required)."""

from reconforge.modules.ip import parse_nmap_output

SAMPLE = """Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for example.com (93.184.216.34)
Host is up (0.042s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http       nginx 1.18.0 (Ubuntu)
443/tcp  open  ssl/http   nginx 1.18.0
3306/tcp open  mysql      MySQL 8.0.36
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds
"""


def test_parses_open_services():
    services = parse_nmap_output(SAMPLE)
    assert len(services) == 5
    ssh = services[0]
    assert ssh["port"] == 22
    assert ssh["proto"] == "tcp"
    assert ssh["state"] == "open"
    assert ssh["service"] == "ssh"
    assert ssh["version"].startswith("OpenSSH 8.9p1")


def test_service_without_version():
    services = parse_nmap_output(SAMPLE)
    proxy = services[-1]
    assert proxy["port"] == 8080
    assert proxy["service"] == "http-proxy"
    assert proxy["version"] == ""


def test_ignores_closed_and_noise():
    text = "81/tcp closed http-alt\n23/tcp open  telnet\nrandom noise line\n"
    services = parse_nmap_output(text)
    assert [s["port"] for s in services] == [23]


def test_empty_output():
    assert parse_nmap_output("") == []
