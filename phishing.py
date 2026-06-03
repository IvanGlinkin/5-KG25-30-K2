#!/usr/bin/env python3

import argparse
import os
import shutil
import tempfile
import json
import sqlite3
import subprocess
import base64
import time
import requests
import urllib3

from selenium import webdriver
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

QWERTY_ADJACENCY: Dict[str, str] = {
    "1": "2q", "2": "13wq", "3": "24ew", "4": "35re", "5": "46tr",
    "6": "57yt", "7": "68uy", "8": "79iu", "9": "80oi", "0": "9po",
    "q": "12wa", "w": "q23esa", "e": "w34rds", "r": "e45tfd",
    "t": "r56ygf", "y": "t67uhg", "u": "y78ijh", "i": "u89okj",
    "o": "i90plk", "p": "o0-l",
    "a": "qwsz", "s": "awedxz", "d": "serfcx",
    "f": "drtgvc", "g": "ftyhbv", "h": "gyujnb", "j": "huikmn",
    "k": "jiolm", "l": "kop",
    "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb",
    "b": "vghn", "n": "bhjm", "m": "njk"
}

HOMOGLYPHS: Dict[str, List[str]] = {
    "a": ["à", "á", "â", "ä", "ã", "å", "ɑ", "@", "4"],
    "b": ["6", "8"],
    "c": ["ç", "ć", "ċ", "¢", "("],
    "d": ["cl"],
    "e": ["è", "é", "ê", "ë", "3"],
    "g": ["9", "q"],
    "h": ["lh", "ll"],
    "i": ["1", "l", "í", "ì", "ï", "!"],
    "l": ["1", "i", "|"],
    "m": ["nn", "rn"],
    "n": ["m", "r"],
    "o": ["0", "ö", "ó", "ò", "ô", "õ"],
    "q": ["g", "9"],
    "s": ["5", "$"],
    "t": ["7", "+"],
    "u": ["ü", "ú", "ù", "û"],
    "v": ["y"],
    "w": ["vv"],
    "x": ["%", "×"],
    "y": ["v", "ÿ"],
    "z": ["2"],
}

VOWELS = "aeiou"
ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
ALLOWED_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-")
MANUAL_STATUSES = {"True positive", "False positive", "Selling"}
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    )
}
CHROME_BIN_CANDIDATES = [
    os.environ.get("CHROME_BIN", ""),
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
]
CHROMEDRIVER_CANDIDATES = [
    os.environ.get("CHROMEDRIVER_BIN", ""),
    "/usr/bin/chromedriver",
    "/usr/lib/chromium/chromedriver",
]

def build_chrome_driver(
    width: int = 800,
    height: int = 600,
    page_timeout: int = 20,
    profile_dir: Optional[str] = None,
) -> webdriver.Chrome:
    options = Options()

    chrome_bin = next((candidate for candidate in CHROME_BIN_CANDIDATES if candidate and os.path.exists(candidate)), None)
    if not chrome_bin:
        raise RuntimeError("Chromium/Chrome binary not found")
    options.binary_location = chrome_bin

    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--ignore-certificate-errors")
    options.add_argument("--allow-running-insecure-content")
    options.add_argument("--disable-software-rasterizer")
    options.add_argument("--disable-features=VizDisplayCompositor")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-background-networking")
    options.add_argument("--no-first-run")
    options.add_argument("--no-default-browser-check")
    options.add_argument("--hide-scrollbars")
    options.add_argument("--mute-audio")
    options.add_argument("--remote-debugging-port=0")
    options.add_argument(f"--window-size={width},{height}")

    xdg_runtime = os.environ.get("XDG_RUNTIME_DIR")
    if xdg_runtime:
        os.makedirs(xdg_runtime, exist_ok=True)

    if profile_dir:
        options.add_argument(f"--user-data-dir={profile_dir}")

    options.set_capability("acceptInsecureCerts", True)

    service_path = next((candidate for candidate in CHROMEDRIVER_CANDIDATES if candidate and os.path.exists(candidate)), None)
    if not service_path:
        raise RuntimeError("chromedriver not found")

    service = Service(service_path)
    driver = webdriver.Chrome(service=service, options=options)
    driver.set_page_load_timeout(page_timeout)
    driver.set_window_size(width, height)
    return driver

def capture_domain_screenshot(
    checked_domain: str,
    fqdn: str,
    root_dir: str = "checking_domains",
    http_timeout: int = 10,
    browser_timeout: int = 20,
    width: int = 800,
    height: int = 600,
    zoom_percent: int = 80,
) -> dict:
    checked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    preflight = resolve_final_http_url(fqdn, timeout=http_timeout)
    if not preflight["ok"]:
        return {
            "domain": fqdn,
            "ok": False,
            "checked_at": checked_at,
            "final_url": preflight.get("final_url"),
            "status_code": preflight.get("status_code"),
            "error": f"Screenshot skipped: final HTTP 200 not reached. {preflight['error']}",
        }

    driver = None
    profile_dir = tempfile.mkdtemp(prefix="chrome-profile-", dir=os.environ.get("TMPDIR", "/tmp"))
    try:
        driver = build_chrome_driver(
            width=width,
            height=height,
            page_timeout=browser_timeout,
            profile_dir=profile_dir,
        )
        driver.get(preflight["final_url"])

        WebDriverWait(driver, browser_timeout).until(
            lambda d: d.execute_script("return document.readyState") == "complete"
        )

        driver.execute_script(
            """
            document.documentElement.style.zoom = arguments[0];
            if (document.body) {
                document.body.style.zoom = arguments[0];
            }
            """,
            f"{zoom_percent}%",
        )

        time.sleep(1.5)

        screenshot_bytes = driver.get_screenshot_as_png()
        screenshot_b64 = base64.b64encode(screenshot_bytes).decode("ascii")

        screenshot_path = build_screenshot_path(checked_domain, fqdn, root_dir=root_dir)
        screenshot_path.write_bytes(screenshot_bytes)

        return {
            "domain": fqdn,
            "ok": True,
            "checked_at": checked_at,
            "final_url": driver.current_url,
            "status_code": 200,
            "screenshot_path": str(screenshot_path),
            "screenshot_base64": screenshot_b64,
        }

    except TimeoutException:
        return {
            "domain": fqdn,
            "ok": False,
            "checked_at": checked_at,
            "final_url": preflight.get("final_url"),
            "status_code": preflight.get("status_code"),
            "error": "Screenshot failed: browser timeout",
        }
    except WebDriverException as e:
        return {
            "domain": fqdn,
            "ok": False,
            "checked_at": checked_at,
            "final_url": preflight.get("final_url"),
            "status_code": preflight.get("status_code"),
            "error": f"Screenshot failed: webdriver error: {e}",
        }
    except Exception as e:
        return {
            "domain": fqdn,
            "ok": False,
            "checked_at": checked_at,
            "final_url": preflight.get("final_url"),
            "status_code": preflight.get("status_code"),
            "error": f"Screenshot failed: {e}",
        }
    finally:
        if driver:
            driver.quit()
        if profile_dir and os.path.isdir(profile_dir):
            shutil.rmtree(profile_dir, ignore_errors=True)

def capture_screenshots_for_domains(
    checked_domain: str,
    domains: List[str],
    root_dir: str = "checking_domains",
    workers: int = 2,
    http_timeout: int = 10,
    browser_timeout: int = 20,
) -> List[dict]:
    unique_domains = sorted(set(domains))
    results = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(
                capture_domain_screenshot,
                checked_domain,
                domain,
                root_dir,
                http_timeout,
                browser_timeout,
            ): domain
            for domain in unique_domains
        }

        for future in as_completed(future_map):
            results.append(future.result())

    results.sort(key=lambda x: x["domain"])
    return results

def update_screenshot_results_in_sqlite(
    checked_domain: str,
    screenshot_results: List[dict],
    root_dir: str = "checking_domains",
) -> Path:
    db_path = build_sqlite_path(checked_domain, root_dir)

    with sqlite3.connect(db_path) as conn:
        init_sqlite_db(conn)

        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("PRAGMA synchronous=FULL")

        for item in screenshot_results:
            row = conn.execute("""
                SELECT
                    "Screenshot",
                    "Final URL",
                    "HTTP Status Code",
                    "Log"
                FROM domains
                WHERE "Checking domain" = ?
            """, (item["domain"],)).fetchone()

            if not row:
                continue

            prev_screenshot, prev_final_url, prev_http_status_code, prev_log = row

            if item["ok"]:
                action = "Screenshot updated" if prev_screenshot else "Screenshot saved"

                new_log = append_log_entry(
                    prev_log,
                    item["checked_at"],
                    f"{action}. Final URL: {item['final_url']}. HTTP status: 200. File: {item['screenshot_path']}."
                )

                conn.execute("""
                    UPDATE domains
                    SET
                        "Screenshot" = ?,
                        "Final URL" = ?,
                        "HTTP Status Code" = ?,
                        "Log" = ?
                    WHERE "Checking domain" = ?
                """, (
                    item["screenshot_base64"],
                    item.get("final_url"),
                    item.get("status_code"),
                    new_log,
                    item["domain"],
                ))
            else:
                new_log = append_log_entry(
                    prev_log,
                    item["checked_at"],
                    item["error"],
                )

                conn.execute("""
                    UPDATE domains
                    SET
                        "Final URL" = COALESCE(?, "Final URL"),
                        "HTTP Status Code" = COALESCE(?, "HTTP Status Code"),
                        "Log" = ?
                    WHERE "Checking domain" = ?
                """, (
                    item.get("final_url"),
                    item.get("status_code"),
                    new_log,
                    item["domain"],
                ))

        conn.commit()

    return db_path

def resolve_final_http_url(domain: str, timeout: int = 10) -> dict:
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    attempts = [
        f"https://{domain}",
        f"http://{domain}",
    ]

    errors = []
    last_final_url = None
    last_status_code = None
    last_content_type = None

    for candidate in attempts:
        try:
            response = session.get(
                candidate,
                allow_redirects=True,
                timeout=timeout,
                verify=False,
            )

            content_type = (response.headers.get("Content-Type") or "").lower()
            final_url = response.url
            last_final_url = final_url
            last_status_code = response.status_code
            last_content_type = content_type

            if response.status_code == 200:
                # html или пустой content-type считаем пригодным для скриншота
                if content_type and ("text/html" not in content_type and "application/xhtml+xml" not in content_type):
                    errors.append(
                        f"{candidate} -> 200 but unsupported content-type: {content_type}"
                    )
                    continue

                return {
                    "ok": True,
                    "start_url": candidate,
                    "final_url": final_url,
                    "status_code": response.status_code,
                    "content_type": content_type,
                }

            errors.append(
                f"{candidate} -> final_url={final_url} status={response.status_code}"
            )

        except requests.RequestException as e:
            errors.append(f"{candidate} -> {e}")

    return {
        "ok": False,
        "error": " | ".join(errors),
        "final_url": last_final_url,
        "status_code": last_status_code,
        "content_type": last_content_type,
    }

def build_screenshot_dir(domain: str, root_dir: str = "checking_domains") -> Path:
    normalized_domain = normalize_input_domain(domain)
    screenshot_dir = Path(root_dir) / normalized_domain / "screenshots"
    screenshot_dir.mkdir(parents=True, exist_ok=True)
    return screenshot_dir

def build_screenshot_path(checked_domain: str, fqdn: str, root_dir: str = "checking_domains") -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    screenshot_dir = build_screenshot_dir(checked_domain, root_dir)
    safe_name = fqdn.replace("/", "_").replace(":", "_")
    return screenshot_dir / f"{safe_name}_{timestamp}.png"

def append_log_entry(existing_log: Optional[str], event_time: str, message: str) -> str:
    entry = f"[{event_time}] {message}"
    if existing_log and existing_log.strip():
        return existing_log.rstrip() + "\n" + entry
    return entry

def extract_ips_from_host_output(output: str) -> List[str]:
    ips = []
    seen = set()

    for raw_line in output.splitlines():
        line = raw_line.strip()

        if " has address " in line:
            ip = line.rsplit(" has address ", 1)[1].strip()
            if ip and ip not in seen:
                seen.add(ip)
                ips.append(ip)

        elif " has IPv6 address " in line:
            ip = line.rsplit(" has IPv6 address ", 1)[1].strip()
            if ip and ip not in seen:
                seen.add(ip)
                ips.append(ip)

    return ips

def run_host_check(domain: str, timeout: int = 5) -> dict:
    try:
        proc = subprocess.run(
            ["host", domain],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return {
            "domain": domain,
            "alive": False,
            "ips": [],
            "ip_address": None,
            "status": "ERROR",
            "log": "host command not found",
        }
    except subprocess.TimeoutExpired:
        return {
            "domain": domain,
            "alive": False,
            "ips": [],
            "ip_address": None,
            "status": "TIMEOUT",
            "log": f"host timeout after {timeout}s",
        }
    except Exception as e:
        return {
            "domain": domain,
            "alive": False,
            "ips": [],
            "ip_address": None,
            "status": "ERROR",
            "log": str(e),
        }

    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()
    combined_output = "\n".join(part for part in [stdout, stderr] if part)

    ips = extract_ips_from_host_output(combined_output)
    alive = len(ips) > 0

    return {
        "domain": domain,
        "alive": alive,
        "ips": ips,
        "ip_address": ", ".join(ips) if ips else None,
        "status": "Unchecked" if alive else "NO_DNS",
        "log": combined_output,
    }

def check_domains_with_host(domains: List[str], workers: int = 32, timeout: int = 5) -> List[dict]:
    unique_domains = sorted(set(domains))
    results = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(run_host_check, domain, timeout): domain
            for domain in unique_domains
        }

        for future in as_completed(future_map):
            results.append(future.result())

    results.sort(key=lambda x: x["domain"])
    return results

def build_sqlite_path(domain: str, root_dir: str = "checking_domains") -> Path:
    normalized_domain = normalize_input_domain(domain)
    db_dir = Path(root_dir) / normalized_domain
    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir / f"{normalized_domain}.sqlite3"


def init_sqlite_db(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS domains (
            "Checking domain" TEXT PRIMARY KEY,
            "First Check Date" TEXT NOT NULL,
            "First live appear date" TEXT,
            "Last check date" TEXT NOT NULL,
            "IP address" TEXT,
            "Screenshot" TEXT,
            "Final URL" TEXT,
            "HTTP Status Code" INTEGER,
            "Status" TEXT,
            "Log" TEXT
        )
    """)

    existing_columns = {
        row[1]
        for row in conn.execute('PRAGMA table_info(domains)').fetchall()
    }

    if 'Final URL' not in existing_columns:
        conn.execute('ALTER TABLE domains ADD COLUMN "Final URL" TEXT')
    if 'HTTP Status Code' not in existing_columns:
        conn.execute('ALTER TABLE domains ADD COLUMN "HTTP Status Code" INTEGER')

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_domains_last_check
        ON domains ("Last check date")
    """)

    conn.commit()

def sync_domains_to_sqlite(
    checked_domain: str,
    found_domains: list[str],
    root_dir: str = "checking_domains",
) -> Path:
    db_path = build_sqlite_path(checked_domain, root_dir)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    unique_domains = sorted(set(found_domains))

    with sqlite3.connect(db_path) as conn:
        init_sqlite_db(conn)

        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("PRAGMA synchronous=FULL")

        for domain in unique_domains:
            initial_log = append_log_entry(
                None,
                now,
                f"First check date: {now}. Domain added to monitoring."
            )

            conn.execute("""
                INSERT INTO domains (
                    "Checking domain",
                    "First Check Date",
                    "First live appear date",
                    "Last check date",
                    "IP address",
                    "Screenshot",
                    "Final URL",
                    "HTTP Status Code",
                    "Status",
                    "Log"
                )
                VALUES (?, ?, NULL, ?, NULL, NULL, NULL, NULL, NULL, ?)
                ON CONFLICT("Checking domain")
                DO UPDATE SET
                    "Last check date" = excluded."Last check date"
            """, (domain, now, now, initial_log))

        conn.commit()

    return db_path

def update_host_results_in_sqlite(
    checked_domain: str,
    host_results: list[dict],
    root_dir: str = "checking_domains",
) -> Path:
    db_path = build_sqlite_path(checked_domain, root_dir)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with sqlite3.connect(db_path) as conn:
        init_sqlite_db(conn)

        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("PRAGMA synchronous=FULL")

        for item in host_results:
            row = conn.execute("""
                SELECT
                    "First live appear date",
                    "IP address",
                    "Status",
                    "Log"
                FROM domains
                WHERE "Checking domain" = ?
            """, (item["domain"],)).fetchone()

            if not row:
                continue

            prev_first_live, prev_ip, prev_status, prev_log = row

            # 1) Домен резолвится
            if item["status"] == "Unchecked":
                new_ip = item["ip_address"]
                new_first_live = prev_first_live
                new_log = prev_log

                if prev_status in MANUAL_STATUSES:
                    new_status = prev_status
                else:
                    new_status = "Unchecked"

                if not prev_first_live:
                    new_first_live = now
                    new_log = append_log_entry(
                        new_log,
                        now,
                        f"First live appear date: {now}. IP address: {new_ip}. Status: {new_status}."
                    )
                elif prev_ip != new_ip:
                    new_log = append_log_entry(
                        new_log,
                        now,
                        f"IP address changed: {prev_ip or 'NULL'} -> {new_ip}."
                    )

                conn.execute("""
                    UPDATE domains
                    SET
                        "First live appear date" = ?,
                        "IP address" = ?,
                        "Status" = ?,
                        "Log" = ?
                    WHERE "Checking domain" = ?
                """, (
                    new_first_live,
                    new_ip,
                    new_status,
                    new_log,
                    item["domain"],
                ))

            # 2) DNS не резолвится
            elif item["status"] == "NO_DNS":
                new_log = prev_log
                had_live_state = bool(prev_first_live or prev_ip)

                if had_live_state:
                    new_log = append_log_entry(
                        new_log,
                        now,
                        f"Domain stopped resolving. Previous First live appear date: {prev_first_live}. "
                        f"Previous IP address: {prev_ip}. First live appear date cleared. "
                        f"IP address cleared. Status: NO_DNS."
                    )

                conn.execute("""
                    UPDATE domains
                    SET
                        "First live appear date" = NULL,
                        "IP address" = NULL,
                        "Status" = 'NO_DNS',
                        "Log" = ?
                    WHERE "Checking domain" = ?
                """, (
                    new_log,
                    item["domain"],
                ))

            # 3) Ошибка/таймаут host — DNS-поля не трогаем
            else:
                new_log = append_log_entry(
                    prev_log,
                    now,
                    f"Host check error. Status: {item['status']}. Details: {item.get('log', '')}"
                )

                conn.execute("""
                    UPDATE domains
                    SET
                        "Final URL" = COALESCE(?, "Final URL"),
                        "HTTP Status Code" = COALESCE(?, "HTTP Status Code"),
                        "Log" = ?
                    WHERE "Checking domain" = ?
                """, (
                    item.get("final_url"),
                    item.get("status_code"),
                    new_log,
                    item["domain"],
                ))

        conn.commit()

    return db_path

def normalize_input_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/", 1)[0]
    return domain


def build_default_output_path(domain: str, fmt: str, root_dir: str = "checking_domains") -> Path:
    normalized_domain = normalize_input_domain(domain)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    extension = "json" if fmt == "json" else "txt"

    output_dir = Path(root_dir) / normalized_domain
    output_dir.mkdir(parents=True, exist_ok=True)

    return output_dir / f"output_{timestamp}.{extension}"

def parse_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/", 1)[0]
    parts = [p for p in domain.split(".") if p]
    if not parts:
        raise ValueError("Некорректный домен")
    if len(parts) == 1:
        return parts[0]
    return parts[-2]


def valid_label(label: str) -> bool:
    if not label:
        return False
    if len(label) > 63:
        return False
    if label.startswith("-") or label.endswith("-"):
        return False
    return all(ch in ALLOWED_CHARS for ch in label)


def valid_tld(tld: str) -> bool:
    if not tld:
        return False
    if len(tld) > 63:
        return False
    return all(ch in ALLOWED_CHARS for ch in tld)


def normalize_token(token: str) -> str:
    token = token.strip().lower().lstrip(".").strip("-")
    return token


def omission(label: str) -> Set[str]:
    return {
        label[:i] + label[i + 1:]
        for i in range(len(label))
        if label[:i] + label[i + 1:]
    }


def transposition(label: str) -> Set[str]:
    out = set()
    for i in range(len(label) - 1):
        if label[i] != label[i + 1]:
            out.add(label[:i] + label[i + 1] + label[i] + label[i + 2:])
    return out


def duplication(label: str) -> Set[str]:
    return {
        label[:i] + label[i] + label[i] + label[i + 1:]
        for i in range(len(label))
    }


def replacement(label: str) -> Set[str]:
    out = set()
    for i, ch in enumerate(label):
        for repl in QWERTY_ADJACENCY.get(ch, ""):
            out.add(label[:i] + repl + label[i + 1:])
    return out


def insertion(label: str) -> Set[str]:
    out = set()
    for i, ch in enumerate(label):
        for neighbor in QWERTY_ADJACENCY.get(ch, ""):
            out.add(label[:i] + neighbor + ch + label[i + 1:])
            out.add(label[:i] + ch + neighbor + label[i + 1:])
    return out


def hyphenation(label: str) -> Set[str]:
    return {
        label[:i] + "-" + label[i:]
        for i in range(1, len(label))
    }


def vowel_swap(label: str) -> Set[str]:
    out = set()
    for i, ch in enumerate(label):
        if ch in VOWELS:
            for v in VOWELS:
                if v != ch:
                    out.add(label[:i] + v + label[i + 1:])
    return out


def bitsquatting(label: str) -> Set[str]:
    out = set()
    for i, ch in enumerate(label):
        c = ord(ch)
        for bit in (1, 2, 4, 8, 16, 32, 64, 128):
            flipped = chr(c ^ bit)
            if flipped in ALLOWED_CHARS:
                out.add(label[:i] + flipped + label[i + 1:])
    return out


def homoglyph(label: str) -> Set[str]:
    out = set()
    for i, ch in enumerate(label):
        for hg in HOMOGLYPHS.get(ch, []):
            out.add(label[:i] + hg + label[i + 1:])
    return out


def prefix_suffix_addition(label: str) -> Set[str]:
    out = set()
    for ch in ALPHABET:
        out.add(ch + label)
        out.add(label + ch)
    return out


def collapse_repeats(label: str) -> Set[str]:
    out = set()
    if not label:
        return out

    chars = [label[0]]
    for ch in label[1:]:
        if ch != chars[-1]:
            chars.append(ch)

    collapsed = "".join(chars)
    if collapsed != label:
        out.add(collapsed)
    return out


def expand_repeats(label: str) -> Set[str]:
    out = set()
    for i, ch in enumerate(label):
        out.add(label[:i] + ch + label[i:])
    return out


def generate_mutations(label: str, ascii_only: bool = True) -> Tuple[Set[str], Dict[str, Set[str]]]:
    families: Dict[str, Set[str]] = {
        "omission": omission(label),
        "transposition": transposition(label),
        "duplication": duplication(label),
        "replacement": replacement(label),
        "insertion": insertion(label),
        "hyphenation": hyphenation(label),
        "vowel_swap": vowel_swap(label),
        "bitsquatting": bitsquatting(label),
        "homoglyph": homoglyph(label),
        "prefix_suffix_addition": prefix_suffix_addition(label),
        "collapse_repeats": collapse_repeats(label),
        "expand_repeats": expand_repeats(label),
    }

    all_mutations: Set[str] = set()

    for family, values in families.items():
        cleaned = set()

        for v in values:
            candidate = v.lower()

            if ascii_only:
                try:
                    candidate.encode("ascii")
                except UnicodeEncodeError:
                    continue

            if valid_label(candidate):
                cleaned.add(candidate)

        families[family] = cleaned
        all_mutations.update(cleaned)

    all_mutations.discard(label)
    return all_mutations, families


def load_tlds(tld_file: Path) -> List[str]:
    tlds = []
    seen = set()

    for line in tld_file.read_text(encoding="utf-8").splitlines():
        tld = normalize_token(line)
        if not tld:
            continue
        if not valid_tld(tld):
            continue
        if tld not in seen:
            seen.add(tld)
            tlds.append(tld)

    return tlds


def load_keywords(keyword_file: Path) -> List[str]:
    keywords = []
    seen = set()

    for line in keyword_file.read_text(encoding="utf-8").splitlines():
        kw = normalize_token(line)
        if not kw:
            continue
        if not valid_label(kw):
            continue
        if kw not in seen:
            seen.add(kw)
            keywords.append(kw)

    return keywords


def combine_labels_with_tlds(labels: Set[str], tlds: List[str]) -> List[str]:
    full_domains = []
    for label in sorted(labels):
        for tld in tlds:
            full_domains.append(f"{label}.{tld}")
    return full_domains


def generate_keyword_labels(base_label: str, keywords: List[str]) -> Set[str]:
    out = set()
    for kw in keywords:
        candidate_1 = f"{base_label}-{kw}"
        candidate_2 = f"{kw}-{base_label}"

        if valid_label(candidate_1):
            out.add(candidate_1)
        if valid_label(candidate_2):
            out.add(candidate_2)
    return out


def generate_keyword_labels_for_many(base_labels: Set[str], keywords: List[str]) -> Set[str]:
    out = set()
    for base_label in base_labels:
        out.update(generate_keyword_labels(base_label, keywords))
    return out


def save_text(lines: List[str], output: Path) -> None:
    with output.open("w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")


def save_json(
    output: Path,
    payload: dict,
) -> None:
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate domain mutations, keyword combinations, and combine them with TLDs."
    )
    parser.add_argument("domain", help="Исходный домен, например hydrattack.com")
    parser.add_argument("--tlds", default="./wordlists/tlds.txt", help="Путь к файлу со списком TLD")
    parser.add_argument("--keywords", default="./wordlists/suffix.txt", help="Путь к файлу со списком keyword'ов")
    parser.add_argument("-o", "--output", help="Файл для сохранения результата")
    parser.add_argument("--format", choices=["txt", "json"], default="txt", help="Формат вывода")
    parser.add_argument("--unicode", action="store_true", help="Разрешить unicode-гомоглифы")
    parser.add_argument("--labels-only", action="store_true", help="Выводить только labels без TLD")
    parser.add_argument("--show-stats", action="store_true", help="Показать статистику")
    parser.add_argument(
        "--keyword-target",
        choices=["base", "mutations", "both"],
        default="base",
        help="К чему применять keyword-комбинации: только к base label, к mutation labels, или ко всему"
    )
    parser.add_argument(
        "--mode",
        choices=["mutations", "keywords", "all"],
        default="all",
        help="Что генерировать: typo-мutations, keyword-комбинации или всё"
    )
    parser.add_argument(
    "--output-root",
    default="checking_domains",
    help="Корневая директория для сохранения результатов"
    )
    parser.add_argument(
    "--host-workers",
    type=int,
    default=32,
    help="Количество параллельных host-проверок"
    )
    parser.add_argument(
    "--host-timeout",
    type=int,
    default=5,
    help="Таймаут одной host-проверки в секундах"
    )
    parser.add_argument(
    "--screenshot-workers",
    type=int,
    default=2,
    help="Количество параллельных selenium-скриншотов"
    )
    parser.add_argument(
        "--http-timeout",
        type=int,
        default=10,
        help="Таймаут preflight HTTP-проверки"
    )
    parser.add_argument(
        "--browser-timeout",
        type=int,
        default=20,
        help="Таймаут загрузки страницы в браузере"
    )

    args = parser.parse_args()

    base_label = parse_domain(args.domain)
    tlds = load_tlds(Path(args.tlds))

    mutations, families = generate_mutations(base_label, ascii_only=not args.unicode)

    keywords: List[str] = []
    keyword_labels: Set[str] = set()

    if args.keywords:
        keywords = load_keywords(Path(args.keywords))

        if args.keyword_target == "base":
            keyword_labels = generate_keyword_labels(base_label, keywords)
        elif args.keyword_target == "mutations":
            keyword_labels = generate_keyword_labels_for_many(mutations, keywords)
        elif args.keyword_target == "both":
            base_and_mutations = set(mutations)
            base_and_mutations.add(base_label)
            keyword_labels = generate_keyword_labels_for_many(base_and_mutations, keywords)

    final_labels: Set[str] = set()

    if args.mode in ("mutations", "all"):
        final_labels.update(mutations)

    if args.mode in ("keywords", "all"):
        final_labels.update(keyword_labels)

    if args.labels_only:
        result = sorted(final_labels)
    else:
        result = combine_labels_with_tlds(final_labels, tlds)

    if args.show_stats:
        print(f"Base label:                {base_label}")
        print(f"TLDs loaded:               {len(tlds)}")
        print(f"Mutations generated:       {len(mutations)}")
        print(f"Keywords loaded:           {len(keywords)}")
        print(f"Keyword labels generated:  {len(keyword_labels)}")
        print(f"Final labels:              {len(final_labels)}")
        print(f"Output rows:               {len(result)}")
        print()
        for family, values in families.items():
            print(f"{family:24s} {len(values)}")
        print()

    output_path = Path(args.output) if args.output else build_default_output_path(
        args.domain,
        args.format,
        args.output_root
    )

    if args.format == "txt":
        save_text(result, output_path)
    else:
        payload = {
            "base_label": base_label,
            "tld_count": len(tlds),
            "mutation_count": len(mutations),
            "keyword_count": len(keywords),
            "keyword_label_count": len(keyword_labels),
            "final_label_count": len(final_labels),
            "output_count": len(result),
            "tlds": tlds,
            "mutations": sorted(mutations),
            "keyword_labels": sorted(keyword_labels),
            "final_labels": sorted(final_labels),
            "output": result,
            "families": {k: sorted(v) for k, v in families.items()},
        }
        save_json(output_path, payload)

    print(f"Saved to: {output_path}")

    db_path = None
    if not args.labels_only:
        db_path = sync_domains_to_sqlite(
            checked_domain=args.domain,
            found_domains=result,
            root_dir=args.output_root,
        )

    if db_path:
        print(f"SQLite DB synced: {db_path}")

    host_results = []
    if not args.labels_only:
        host_results = check_domains_with_host(
            result,
            workers=args.host_workers,
            timeout=args.host_timeout,
        )

        update_host_results_in_sqlite(
            checked_domain=args.domain,
            host_results=host_results,
            root_dir=args.output_root,
        )

        live_count = sum(1 for item in host_results if item["alive"])
        print(f"Host check finished: {live_count}/{len(host_results)} domains resolved")

    live_domains = [
        item["domain"]
        for item in host_results
        if item["status"] == "Unchecked"
    ]

    screenshot_results = []
    if live_domains:
        screenshot_results = capture_screenshots_for_domains(
            checked_domain=args.domain,
            domains=live_domains,
            root_dir=args.output_root,
            workers=args.screenshot_workers,
            http_timeout=args.http_timeout,
            browser_timeout=args.browser_timeout,
        )

        update_screenshot_results_in_sqlite(
            checked_domain=args.domain,
            screenshot_results=screenshot_results,
            root_dir=args.output_root,
        )

        screenshot_ok = sum(1 for item in screenshot_results if item["ok"])
        print(f"Screenshots finished: {screenshot_ok}/{len(screenshot_results)} saved")
        if screenshot_ok < len(screenshot_results):
            failed = [item for item in screenshot_results if not item["ok"]]
            print("Screenshot failures (up to 5):")
            for item in failed[:5]:
                print(f"  - {item['domain']}: {item.get('error', 'unknown error')}")

if __name__ == "__main__":
    main()