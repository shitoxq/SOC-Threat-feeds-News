#!/usr/bin/env python3
"""
GDPFMIT SOC Real-Time Threat Intelligence Monitor
Fetches feeds, deduplicates against past alerts, structures details into 
a standardized CTI template via Gemini AI, and dispatches alerts to Telegram.
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

# Load Secrets from Environment Variables
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
    """Strips raw HTML tags and unescapes entities for Telegram HTML mode."""
    if not text:
        return ""
    clean = re.sub(r'<[^>]+>', '', text)
    return html.escape(html.unescape(clean)).strip()

def load_sent_cache():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_sent_cache(sent_list):
    try:
        # Keep last 500 items preserving explicit FIFO order
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

def generate_dynamic_alert(title, pub_date, desc, link):
    api_key = os.getenv("GEMINI_API_KEY")
    
    # Static HTML Fallback matching exact requested template schema
    fallback_alert = f"""🚨 <b>SOC Cyber Threat Intelligence Alert</b>

<b>Title:</b> {sanitize_html(title.strip())}
<b>Date:</b> {pub_date[:16]}
<b>Severity:</b> 🟠 High
<b>Category:</b> Vulnerability / Exploit / Malware
<b>Threat Actor:</b> Unknown / Unspecified
<b>Affected Product/Organization:</b> Software Systems
<b>CVE:</b> See source link

📝 <b>Summary:</b> 
{sanitize_html(desc.strip()[:350])}...

💥 <b>Impact:</b> 
Potential unauthorized system compromise, remote execution, or enterprise risk.

🔍 <b>IOCs:</b> 
See source link for full indicator listing.

🛡️ <b>Recommended Action:</b> 
• Apply relevant vendor security patches immediately.
• Review perimeter firewall logs and endpoint monitoring rules.

🔗 <b>Source:</b> {link}"""

    if not api_key:
        return fallback_alert

    prompt = f"""You are a Senior Cyber Threat Intelligence Analyst.
Analyze this threat news item:
Title: {title}
Description: {desc}
URL: {link}

Generate a concise threat alert using HTML tags (like <b>bold</b>) following this EXACT template structure:

🚨 <b>SOC Cyber Threat Intelligence Alert</b>

<b>Title:</b> [Concise, professional title summarizing the threat]
<b>Date:</b> {pub_date[:16]}
<b>Severity:</b> [🔴 Critical / 🟠 High / 🟡 Medium / 🟢 Low]
<b>Category:</b> [Malware, Ransomware, Vulnerability, Phishing, APT, Zero-Day, etc.]
<b>Threat Actor:</b> [APT/Group Name if mentioned, otherwise "Unknown / Unspecified"]
<b>Affected Product/Organization:</b> [Specific software, OS, vendor, or target industry]
<b>CVE:</b> [CVE ID(s) if mentioned, otherwise "N/A"]

📝 <b>Summary:</b> 
[2–3 concise sentences summarizing what happened]

💥 <b>Impact:</b> 
[Direct business or enterprise security impact]

🔍 <b>IOCs:</b> 
[Hashes, IPs, domains, or "See source link"]

🛡️ <b>Recommended Action:</b> 
• [Specific mitigation step 1]
• [Specific mitigation step 2]

🔗 <b>Source:</b> {link}

Output ONLY the final HTML alert. Do NOT wrap output in markdown code blocks like ```html or ```markdown."""

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    payload = {
        "contents": [{
            "parts": [{"text": prompt}]
        }]
    }
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            generated_text = data["candidates"][0]["content"]["parts"][0]["text"]
            cleaned_text = generated_text.replace("```html", "").replace("```markdown", "").replace("```", "").strip()
            return cleaned_text
    except Exception as e:
        print(f"[-] Gemini API failed, using fallback template: {e}", file=sys.stderr)
        return fallback_alert

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

            vendor = item.get("vendorProject", "Unknown")
            product = item.get("product", "Unknown")
            date_added = item.get("dateAdded", datetime.now().strftime("%Y-%m-%d"))
            desc = item.get("shortDescription", "")
            action = item.get("requiredAction", "")
            link = "[https://www.cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)"

            raw_title = f"CISA KEV: Active Exploitation of {vendor} {product} ({cve_id})"
            raw_desc = f"{desc} Required Action: {action}"
            
            # Route KEV alert through Gemini for dynamic AI parsing & formatting
            alert = generate_dynamic_alert(raw_title, date_added, raw_desc, link)
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

            # Route RSS item through Gemini for dynamic AI parsing & formatting
            alert = generate_dynamic_alert(title, pub_date, desc, link)
            new_alerts.append((item_hash, alert))
    except Exception as e:
        print(f"[-] RSS {feed_key} error: {e}", file=sys.stderr)
    return new_alerts

def main():
    print(f"[*] Starting Real-Time Threat Intel Scan at {datetime.now().isoformat()}...")
    sent_cache = load_sent_cache()
    new_items_found = 0

    # 1. Process CISA KEV Feed via AI
    kev_alerts = check_cisa_kev(sent_cache)
    for h, alert_text in kev_alerts:
        print(f"[+] Sending new KEV alert: {h}")
        if send_telegram_alert(alert_text):
            sent_cache.append(h)
            new_items_found += 1

    # 2. Process RSS Feeds via AI
    for feed_key, feed_url in FEEDS.items():
        if feed_key == "cisa_kev":
            continue
        
        print(f"[*] Scanning feed: {feed_key}...")
        rss_alerts = check_rss_feed(feed_key, feed_url, sent_cache)
        for h, alert_text in rss_alerts:
            print(f"[+] Sending new {feed_key} alert: {h}")
            if send_telegram_alert(alert_text):
                sent_cache.append(h)
                new_items_found += 1

    # Save cache preserving state order
    save_sent_cache(sent_cache)
    print(f"[*] Scan complete. Delivered {new_items_found} new alerts.")

if __name__ == "__main__":
    main()
