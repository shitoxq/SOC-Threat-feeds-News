#!/usr/bin/env python3
"""
GDPFMIT SOC Cybersecurity Threat Intelligence Engine
Automated Feed Gatherer, Formatter & Telegram Dispatcher
"""

import os
import sys
import json
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime

# Configuration (read from environment variables with defaults)
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "8851782460:AAHjRPVhHzMoWDf3_DFsC-TPQz_UF-qu92s")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "-1004385697303")

FEEDS = {
    "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "the_hacker_news": "https://feeds.feedburner.com/TheHackersNews",
    "bleeping_computer": "https://www.bleepingcomputer.com/feed/"
}

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) GDPFMIT-SOC/4.0"}

def fetch_url(url):
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read()
    except Exception as e:
        print(f"[-] Error fetching {url}: {e}", file=sys.stderr)
        return None

def get_cisa_kev_items():
    data = fetch_url(FEEDS["cisa_kev"])
    if not data:
        return []
    try:
        payload = json.loads(data.decode("utf-8"))
        vulns = payload.get("vulnerabilities", [])
        sorted_vulns = sorted(vulns, key=lambda x: x.get("dateAdded", ""), reverse=True)
        return sorted_vulns[:2]
    except Exception as e:
        print(f"[-] Error parsing CISA KEV: {e}", file=sys.stderr)
        return []

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
            if res.get("ok"):
                print(f"[+] Alert sent successfully.")
                return True
            else:
                print(f"[-] Telegram error: {res}", file=sys.stderr)
                return False
    except Exception as e:
        print(f"[-] Telegram dispatch exception: {e}", file=sys.stderr)
        return False

def build_kev_alert(kev_item):
    cve_id = kev_item.get("cveID", "N/A")
    vendor = kev_item.get("vendorProject", "Unknown")
    product = kev_item.get("product", "Unknown")
    date_added = kev_item.get("dateAdded", datetime.now().strftime("%Y-%m-%d"))
    desc = kev_item.get("shortDescription", "")
    action = kev_item.get("requiredAction", "Apply official vendor security patches immediately.")
    
    alert = f"""🚨 *CRITICAL Cybersecurity Threat Alert*

📌 *Title:* Active Exploitation of {vendor} {product} ({cve_id})
📅 *Date:* {date_added}
🏷️ *Threat Type:* Vulnerability / Exploit
⚡ *Severity:* 🔴 Critical
🎯 *Target:* {vendor} {product} Deployments
🔢 *CVE / IOC:* {cve_id} (CISA KEV)

📝 *What Happened:*
CISA has added {cve_id} affecting {vendor} {product} to the Known Exploited Vulnerabilities catalog. {desc} Threat actors are actively exploiting this in the wild.

💥 *Impact:*
Unauthenticated access, unauthorized code execution, potential hypervisor or server compromise, and lateral movement.

🛡️ *Recommended Action:*
• {action}
• Isolate management interfaces from direct public internet exposure.
• Audit recent access logs and user accounts for abnormal persistence.

🔍 *SOC Detection:*
Monitor perimeter firewall, reverse proxy, and web server access logs for anomalous requests targeting {product}. Alert on unexpected child process creation under service accounts. MITRE ATT&CK: T1190 (Exploit Public-Facing Application).

🔗 *Source:* https://www.cisa.gov/known-exploited-vulnerabilities-catalog"""
    return alert

def main():
    print(f"[*] Starting GDPFMIT Threat Intelligence Run at {datetime.now().isoformat()}...")
    kev_items = get_cisa_kev_items()
    if kev_items:
        for item in kev_items[:2]:
            alert_text = build_kev_alert(item)
            print(f"[*] Sending KEV Alert: {item.get('cveID')}")
            send_telegram_alert(alert_text)
            
    print("[*] Threat Intelligence Run Complete.")

if __name__ == "__main__":
    main()
