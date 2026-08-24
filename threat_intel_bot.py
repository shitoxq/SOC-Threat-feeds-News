#!/usr/bin/env python3
"""
GDPFMIT SOC Real-Time Threat Intelligence Monitor
Fetches feeds, deduplicates against past alerts, and only sends NEW news items to Telegram.
"""

import os
import sys
import json
import hashlib
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "8851782460:AAHjRPVhHzMoWDf3_DFsC-TPQz_UF-qu92s")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "-1004385697303")
STATE_FILE = "sent_alerts.json"

FEEDS = {
    "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "the_hacker_news": "https://feeds.feedburner.com/TheHackersNews",
    "bleeping_computer": "https://www.bleepingcomputer.com/feed/"
}

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) GDPFMIT-SOC-Realtime/4.0"}

def load_sent_cache():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return set(json.load(f))
        except Exception:
            return set()
    return set()

def save_sent_cache(sent_set):
    try:
        # Keep last 500 hashes to maintain reasonable cache size
        trimmed = list(sent_set)[-500:]
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

def send_telegram_alert(message_text):
    endpoint = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": message_text,
        "parse_mode": "Markdown",
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
        # Check newest 5 entries
        for item in sorted(vulns, key=lambda x: x.get("dateAdded", ""), reverse=True)[:5]:
            cve_id = item.get("cveID", "")
            item_hash = f"KEV_{cve_id}"
            if item_hash in sent_cache:
                continue

            vendor = item.get("vendorProject", "Unknown")
            product = item.get("product", "Unknown")
            date_added = item.get("dateAdded", datetime.now().strftime("%Y-%m-%d"))
            desc = item.get("shortDescription", "")
            action = item.get("requiredAction", "Apply official security update.")

            alert = f"""🚨 *CRITICAL Cybersecurity Threat Alert*

📌 *Title:* Active Exploitation of {vendor} {product} ({cve_id})
📅 *Date:* {date_added}
🏷️ *Threat Type:* Vulnerability / Exploit
⚡ *Severity:* 🔴 Critical
🎯 *Target:* {vendor} {product} Deployments
🔢 *CVE / IOC:* {cve_id} (CISA KEV)

📝 *What Happened:*
CISA has added {cve_id} ({vendor} {product}) to the Known Exploited Vulnerabilities catalog. {desc} Threat actors are actively exploiting this in the wild.

💥 *Impact:*
Unauthorized system compromise, remote execution, and lateral enterprise risk.

🛡️ *Recommended Action:*
• {action}
• Isolate management interfaces from direct internet access.
• Check logs for indicators of compromise.

🔍 *SOC Detection:*
Monitor perimeter logs and WAF for exploitation attempts against {product}. MITRE ATT&CK: T1190 (Exploit Public-Facing Application).

🔗 *Source:* https://www.cisa.gov/known-exploited-vulnerabilities-catalog"""
            
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
            title = item.find("title").text if item.find("title") is not None else ""
            link = item.find("link").text if item.find("link") is not None else ""
            pub_date = item.find("pubDate").text if item.find("pubDate") is not None else datetime.now().strftime("%Y-%m-%d")
            desc = item.find("description").text if item.find("description") is not None else ""
            
            # Clean HTML tags from description if needed
            clean_desc = desc.replace("<p>", "").replace("</p>", "").replace("<b>", "").replace("</b>", "")[:350]

            item_hash = hashlib.sha256(link.strip().encode("utf-8")).hexdigest()
            if item_hash in sent_cache:
                continue

            alert = f"""🚨 *HIGH Cybersecurity Threat Alert*

📌 *Title:* {title.strip()}
📅 *Date:* {pub_date[:16]}
🏷️ *Threat Type:* Malware / Vulnerability / Threat Campaign
⚡ *Severity:* 🟠 High
🎯 *Target:* Enterprise Infrastructure & Software Systems
🔢 *CVE / IOC:* See linked advisory

📝 *What Happened:*
{clean_desc.strip()}...

💥 *Impact:*
Potential unauthorized access, service disruption, or data compromise depending on affected systems.

🛡️ *Recommended Action:*
• Review affected software versions in your environment.
• Apply relevant vendor updates or mitigations.
• Verify firewall and endpoint monitoring rules.

🔍 *SOC Detection:*
Inspect perimeter network and endpoint telemetry for related IOCs. MITRE ATT&CK: T1190, T1059.

🔗 *Source:* {link.strip()}"""

            new_alerts.append((item_hash, alert))
    except Exception as e:
        print(f"[-] RSS {feed_key} error: {e}", file=sys.stderr)
    return new_alerts

def main():
    print(f"[*] Starting Real-Time Threat Intel Scan at {datetime.now().isoformat()}...")
    sent_cache = load_sent_cache()
    new_items_found = 0

    # 1. Check CISA KEV for new additions
    kev_alerts = check_cisa_kev(sent_cache)
    for h, alert_text in kev_alerts:
        print(f"[+] Sending new KEV alert: {h}")
        if send_telegram_alert(alert_text):
            sent_cache.add(h)
            new_items_found += 1

    # 2. Check The Hacker News
    thn_alerts = check_rss_feed("the_hacker_news", FEEDS["the_hacker_news"], sent_cache)
    for h, alert_text in thn_alerts:
        print(f"[+] Sending new THN alert: {h}")
        if send_telegram_alert(alert_text):
            sent_cache.add(h)
            new_items_found += 1

    # 3. Check BleepingComputer
    bc_alerts = check_rss_feed("bleeping_computer", FEEDS["bleeping_computer"], sent_cache)
    for h, alert_text in bc_alerts:
        print(f"[+] Sending new BleepingComputer alert: {h}")
        if send_telegram_alert(alert_text):
            sent_cache.add(h)
            new_items_found += 1

    # Save state
    save_sent_cache(sent_cache)
    print(f"[*] Scan complete. Delivered {new_items_found} new alerts.")

if __name__ == "__main__":
    main()
