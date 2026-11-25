#!/usr/bin/env python3
"""Fail-closed check for personal values (emails, IPs, MACs, private word list).

Usage:
    python -I scripts/check_repo.py [ROOT]            # development check, skips private/
    python -I scripts/check_repo.py --publish ROOT    # public-copy check, no skips

Messages name the file, line and kind of value, never the value itself.
Exit code 0 means clean, 1 means findings, 2 means the check could not run.

Allowed by design:
- Emails: example.com (and subdomains), *.invalid, git@github.com,
  noreply@github.com, the GitHub Actions bot address.
- IPv4: loopback, 0.0.0.0, the example network 192.168.100.0/24, the
  documentation ranges, a few well-known public resolvers, multicast, and
  whole-range blocks written as CIDR with a prefix of /16 or wider
  (for example 172.16.0.0/12), which name a range rather than a host.
- MACs: only the documentation range 00:00:5E:00:53:xx.
- Exact strings listed in scripts/check-allow.txt (for version numbers that
  look like addresses). Never put a personal value in that file.

The private word list is read from $PRIVATE_WORDLIST_FILE, else
wordlist.local at ROOT. It is applied to file content and file paths.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import subprocess
import sys
from pathlib import Path

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
IPV4_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(/\d{1,2})?(?![\d.]*\d)")
MAC_RE = re.compile(r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])")

ALLOWED_EMAIL_RE = re.compile(
    r"(@(?:[A-Za-z0-9-]+\.)*example\.(?:com|org|net)$|\.invalid$|^git@github\.com$|^noreply@github\.com$"
    r"|^41898282\+github-actions\[bot\]@users\.noreply\.github\.com$)",
    re.I,
)
EXAMPLE_NET = ipaddress.ip_network("192.168.100.0/24")
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
WELL_KNOWN = {
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220", "255.255.255.255", "0.0.0.0",
}
MAC_DOC_PREFIX = "00:00:5e:00:53:"


def ip_allowed(addr: str, prefix: str | None) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return True  # not an address (e.g. 999.1.1.1)
    if prefix is not None and int(prefix[1:]) <= 16:
        return True  # a whole range, not a host
    if addr in WELL_KNOWN or ip.is_loopback or ip.is_multicast or ip.is_unspecified:
        return True
    if ip in EXAMPLE_NET or any(ip in n for n in DOC_NETS):
        return True
    return False


def load_wordlist(root: Path) -> list[re.Pattern] | None:
    path = Path(os.environ.get("PRIVATE_WORDLIST_FILE") or root / "wordlist.local")
    if not path.is_file():
        return None
    pats = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            pats.append(re.compile(line, re.I))
    return pats


def load_allow(root: Path) -> set[str]:
    path = root / "scripts" / "check-allow.txt"
    if not path.is_file():
        return set()
    out = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.add(line)
    return out


def load_binaries(root: Path) -> dict[str, str]:
    """Reviewed binary files: {path: sha256} from scripts/check-binaries.txt."""
    path = root / "scripts" / "check-binaries.txt"
    out: dict[str, str] = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                digest, rel = line.split(None, 1)
                out[rel.strip()] = digest.lower()
    return out


def list_files(root: Path) -> list[str]:
    try:
        res = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            capture_output=True, check=True,
        )
        files = [f for f in res.stdout.decode("utf-8").split("\0") if f]
    except (OSError, subprocess.CalledProcessError):
        files = [
            str(p.relative_to(root)).replace(os.sep, "/")
            for p in root.rglob("*") if p.is_file() and ".git" not in p.parts
        ]
    return sorted(f for f in files if (root / f).is_file())


def check(root: Path, publish: bool) -> tuple[list[str], list[str]]:
    """Return (findings, notes). Findings fail the check."""
    findings: list[str] = []
    notes: list[str] = []
    words = load_wordlist(root)
    if words is None or not words:
        msg = "private word list is missing or empty"
        (findings if publish else notes).append(msg)
        words = words or []
    allow = load_allow(root)
    binaries = load_binaries(root)

    for rel in list_files(root):
        if rel == "wordlist.local":
            continue
        if not publish and (rel.startswith("private/") or rel == "private"):
            continue
        hits = sum(1 for p in words if p.search(rel))
        if hits:
            findings.append(f"{rel}: word list matches the file path")
        data = (root / rel).read_bytes()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            if publish and binaries.get(rel) != hashlib.sha256(data).hexdigest():
                findings.append(f"{rel}: not UTF-8 text and not in scripts/check-binaries.txt")
            else:
                notes.append(f"{rel}: binary, pattern checks skipped")
            text = data.decode("latin-1")
            n = sum(len(p.findall(text)) for p in words)
            if n:
                findings.append(f"{rel}: word list matches in binary content ({n})")
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            where = f"{rel}:{lineno}"
            for p in words:
                if p.search(line):
                    findings.append(f"{where}: word list match")
                    break
            for m in EMAIL_RE.finditer(line):
                if m.group(0) not in allow and not ALLOWED_EMAIL_RE.search(m.group(0)):
                    findings.append(f"{where}: email address")
            for m in IPV4_RE.finditer(line):
                if m.group(1) in allow or m.group(0) in allow:
                    continue
                if not ip_allowed(m.group(1), m.group(2)):
                    findings.append(f"{where}: IP address")
            for m in MAC_RE.finditer(line):
                mac = m.group(0).lower().replace("-", ":")
                if not mac.startswith(MAC_DOC_PREFIX):
                    findings.append(f"{where}: MAC address")
    return findings, notes


def main(argv: list[str]) -> int:
    publish = "--publish" in argv
    args = [a for a in argv if not a.startswith("--")]
    root = Path(args[0] if args else ".").resolve()
    if not root.is_dir():
        print(f"check_repo: not a directory: {root}", file=sys.stderr)
        return 2
    try:
        findings, notes = check(root, publish)
    except re.error as e:
        print(f"check_repo: word list has an invalid pattern ({e.msg})", file=sys.stderr)
        return 2
    for n in notes:
        print(f"note: {n}")
    for f in findings:
        print(f"FAIL: {f}")
    print(f"check_repo: {len(findings)} finding(s){' (publish mode)' if publish else ''}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
