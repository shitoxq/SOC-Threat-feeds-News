#!/usr/bin/env python3
"""
GDPFMIT SOC Real-Time Threat Intelligence Monitor
"""

import os
import sys
import json
import re
import html
import hashlib
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
STATE_FILE = "sent_alerts.json"

if not BOT_TOKEN or not CHAT_ID:
    sys.exit("[-] Error: TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID environment variables must be set.")

FEEDS = {
    "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "the_hacker_news": "https://feeds.feedburner.com/TheHackersNews",
    "bleeping_computer": "https://www.bleepingcomputer.com/feed/",
    "ipurple_team": "https://ipurple.team/feed/",
    "securityweek": "https://www.securityweek.com/feed/",
    "sc_magazine": "https://www.scworld.com/feed/",
    "dark_reading": "https://www.darkreading.com/rss/all.xml",
    "infosecurity_magazine": "https://www.infosecurity-magazine.com/rss/news/",
    "help_net_security": "https://www.helpnetsecurity.com/feed/",
    "ciso_series": "https://cisoseries.com/feed/",
    "security_boulevard": "https://securityboulevard.com/feed/",
    "ehackingnews": "https://www.ehackingnews.com/feeds/posts/default?alt=rss"
}

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) GDPFMIT-SOC-Realtime/4.0"}

def sanitize_html(text):
    """Strips HTML tags and unescapes entities for Telegram HTML mode."""
    if not text:
        return ""
    clean = re.sub(r'<[^>]+>', '', text)
    return html.escape(html.unescape(clean)).strip()

def load_sent_cache():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)  # List preserves FIFO order
        except Exception:
            return []
    return []

def save_sent_cache(sent_list):
    try:
        # Keep last 500 items preserving order
        trimmed = sent_list[-500:]
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(trimmed, f, indent=2)
    except Exception as e:
        print(f"[-] Error saving cache: {e}", file=sys.stderr)

def fetch_url(url):
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read()
    except Exception as e:
        print(f"[-] Error fetching {url}: {e}", file=sys.stderr)
        return None

def send_telegram_alert(message_html):
    endpoint = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": message_html,
        "parse_mode": "HTML",
        "link_preview_options": {
            "is_disabled": False,
            "prefer_large_media": True,
            "show_above_text": True
        }
    }
    req = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": HEADERS["User-Agent"]}
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            res = json.loads(resp.read().decode("utf-8"))
            return res.get("ok", False)
    except Exception as e:
        print(f"[-] Telegram dispatch error: {e}", file=sys.stderr)
        return False

def check_cisa_kev(sent_cache):
    new_alerts = []
    data = fetch_url(FEEDS["cisa_kev"])
    if not data:
        return new_alerts
    try:
        payload = json.loads(data.decode("utf-8"))
        vulns = payload.get("vulnerabilities", [])
        for item in sorted(vulns, key=lambda x: x.get("dateAdded", ""), reverse=True)[:5]:
            cve_id = item.get("cveID", "")
            item_hash = f"KEV_{cve_id}"
            if item_hash in sent_cache:
                continue

            vendor = html.escape(item.get("vendorProject", "Unknown"))
            product = html.escape(item.get("product", "Unknown"))
            date_added = item.get("dateAdded", datetime.now().strftime("%Y-%m-%d"))
            desc = html.escape(item.get("shortDescription", ""))
            action = html.escape(item.get("requiredAction", "Apply official security update."))

            alert = f"""🚨 <b>CRITICAL Cybersecurity Threat Alert</b>

📌 <b>Title:</b> Active Exploitation of {vendor} {product} ({cve_id})
📅 <b>Date:</b> {date_added}
🏷️ <b>Threat Type:</b> Vulnerability / Exploit
⚡ <b>Severity:</b> 🔴 Critical
🎯 <b>Target:</b> {vendor} {product} Deployments
🔢 <b>CVE / IOC:</b> {cve_id} (CISA KEV)

📝 <b>What Happened:</b>
CISA added {cve_id} ({vendor} {product}) to KEV catalog. {desc} Active in wild.

💥 <b>Impact:</b>
Unauthorized system compromise and remote execution.

🛡️ <b>Recommended Action:</b>
• {action}
• Isolate management interfaces from direct internet access.

🔗 <b>Source:</b> https://www.cisa.gov/known-exploited-vulnerabilities-catalog"""
            
            new_alerts.append((item_hash, alert))
    except Exception as e:
        print(f"[-] KEV check error: {e}", file=sys.stderr)
    return new_alerts

def check_rss_feed(feed_key, feed_url, sent_cache):
    new_alerts = []
    data = fetch_url(feed_url)
    if not data:
        return new_alerts
    try:
        root = ET.fromstring(data)
        for item in root.findall(".//item")[:3]:
            title = sanitize_html(item.findtext("title", ""))
            link = item.findtext("link", "").strip()
            pub_date = item.findtext("pubDate", datetime.now().strftime("%Y-%m-%d"))
            desc = sanitize_html(item.findtext("description", ""))[:350]
            
            item_hash = hashlib.sha256(link.encode("utf-8")).hexdigest()
            if item_hash in sent_cache:
                continue

            alert = f"""🚨 <b>HIGH Cybersecurity Threat Alert</b>

📌 <b>Title:</b> {title}
📅 <b>Date:</b> {pub_date[:16]}
🏷️ <b>Threat Type:</b> Vulnerability / Exploit / Malware
⚡ <b>Severity:</b> 🟠 High
🎯 <b>Target:</b> Software Systems

📝 <b>What Happened:</b>
{desc}...

🔗 <b>Source:</b> {link}"""
            
            new_alerts.append((item_hash, alert))
    except Exception as e:
        print(f"[-] RSS {feed_key} error: {e}", file=sys.stderr)
    return new_alerts

def main():
    print(f"[*] Starting Real-Time Threat Intel Scan at {datetime.now().isoformat()}...")
    sent_cache = load_sent_cache()
    new_items_found = 0

    kev_alerts = check_cisa_kev(sent_cache)
    for h, alert_text in kev_alerts:
        if send_telegram_alert(alert_text):
            sent_cache.append(h)
            new_items_found += 1

    for feed_key, feed_url in FEEDS.items():
        if feed_key == "cisa_kev":
            continue
        rss_alerts = check_rss_feed(feed_key, feed_url, sent_cache)
        for h, alert_text in rss_alerts:
            if send_telegram_alert(alert_text):
                sent_cache.append(h)
                new_items_found += 1

    save_sent_cache(sent_cache)
    print(f"[*] Scan complete. Delivered {new_items_found} new alerts.")

if __name__ == "__main__":
    main()
