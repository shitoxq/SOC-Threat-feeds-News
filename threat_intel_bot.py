#!/usr/bin/env python3
"""
GDPFMIT SOC Real-Time Threat Intelligence Monitor
Fetches feeds, processes items sequentially (waiting for Gemini AI summaries),
and sends structured HTML alerts to Telegram.
"""

import os
import sys
import json
import re
import html
import hashlib
import tempfile
import time
import urllib.request
import urllib.error
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

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) GDPFMIT-SOC-Realtime/5.0"}

def sanitize_html(text):
    """Strips raw HTML tags and unescapes entities safely for Telegram HTML mode."""
    if not text:
        return ""
    clean = re.sub(r'<[^>]+>', '', text)
    return html.escape(html.unescape(clean)).strip()

def load_sent_cache():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
        except Exception as e:
            print(f"[-] Cache load error (starting fresh): {e}", file=sys.stderr)
            return []
    return []

def save_sent_cache(sent_list):
    """Atomic save operation to prevent state corruption."""
    try:
        trimmed = sent_list[-500:]
        dir_name = os.path.dirname(STATE_FILE) or "."
        with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, encoding="utf-8") as tf:
            json.dump(trimmed, tf, indent=2)
            temp_name = tf.name
        os.replace(temp_name, STATE_FILE)
    except Exception as e:
        print(f"[-] Error saving cache state: {e}", file=sys.stderr)

def fetch_url(url):
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=20) as resp:
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
        with urllib.request.urlopen(req, timeout=20) as resp:
            res = json.loads(resp.read().decode("utf-8"))
            return res.get("ok", False)
    except Exception as e:
        print(f"[-] Telegram dispatch error: {e}", file=sys.stderr)
        return False

def generate_dynamic_alert(title, pub_date, desc, link):
    """
    Blocks execution and waits for Gemini to analyze and summarize the news.
    Includes explicit API diagnostics to debug any failure.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    
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
        print("[-] Missing GEMINI_API_KEY. Using fallback template.", file=sys.stderr)
        return fallback_alert

    prompt = f"""You are a Senior Cyber Threat Intelligence Analyst.
Analyze and dynamically summarize this threat intelligence news item:
Title: {title}
Description: {desc}
URL: {link}

Generate a concise threat alert using HTML tags following this EXACT template structure:

🚨 <b>SOC Cyber Threat Intelligence Alert</b>

<b>Title:</b> [Synthesize a clear, threat-focused professional title]
<b>Date:</b> {pub_date[:16]}
<b>Severity:</b> [🔴 Critical / 🟠 High / 🟡 Medium / 🟢 Low]
<b>Category:</b> [Specific category, e.g., Ransomware, Zero-Day, Critical Infrastructure, APT, Phishing, etc.]
<b>Threat Actor:</b> [Name of APT or group if mentioned, e.g., "Iranian Threat Actors", otherwise "Unknown / Unspecified"]
<b>Affected Product/Organization:</b> [Identify specific targeted software, vendor, or infrastructure, e.g., "UK Power Plant / CNI Infrastructure"]
<b>CVE:</b> [CVE ID(s) if mentioned, otherwise "N/A"]

📝 <b>Summary:</b> 
[Write 2–3 concise sentences summarizing the event, threat vector, and target impact]

💥 <b>Impact:</b> 
[Direct technical, operational, or business risk]

🔍 <b>IOCs:</b> 
[Hashes, IP ranges, domains, or "See source link"]

🛡️ <b>Recommended Action:</b> 
• [Specific remediation step 1]
• [Specific monitoring step 2]

🔗 <b>Source:</b> {link}

Output raw HTML only. Do NOT output markdown code blocks like ```html or ```."""

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    payload = {
        "contents": [{
            "parts": [{"text": prompt}]
        }],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 800
        }
    }
    
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        # Block and wait up to 30 seconds for Gemini response
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            
            candidates = data.get("candidates", [])
            if not candidates:
                print("[-] Gemini safety block triggered. Reverting to fallback.", file=sys.stderr)
                return fallback_alert
                
            parts = candidates[0].get("content", {}).get("parts", [])
            if not parts:
                return fallback_alert
                
            generated_text = parts[0].get("text", "")
            cleaned_text = re.sub(r'^```html\s*|^```markdown\s*|^```\s*|```$', '', generated_text.strip(), flags=re.MULTILINE).strip()
            return cleaned_text
            
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8")
        print(f"[-] Gemini API HTTP Error {e.code}: {error_body}", file=sys.stderr)
        return fallback_alert
    except Exception as e:
        print(f"[-] Gemini API Request Failed: {e}", file=sys.stderr)
        return fallback_alert

def process_single_item(title, pub_date, desc, link, item_hash, sent_cache):
    """Processes a single news item end-to-end sequentially."""
    if item_hash in sent_cache:
        return False

    print(f"[>] Generating AI summary for: {title[:50]}...")
    
    # 1. Wait until AI generates summary
    alert_text = generate_dynamic_alert(title, pub_date, desc, link)
    
    # 2. Dispatch alert to Telegram
    print(f"[+] Sending alert to Telegram for hash: {item_hash[:10]}...")
    if send_telegram_alert(alert_text):
        sent_cache.append(item_hash)
        save_sent_cache(sent_cache)
        # 3. Pause 2 seconds before moving to the next item to prevent API rate limiting
        time.sleep(2)
        return True
    
    return False

def check_cisa_kev(sent_cache):
    new_count = 0
    data = fetch_url(FEEDS["cisa_kev"])
    if not data:
        return new_count
    try:
        payload = json.loads(data.decode("utf-8"))
        vulns = payload.get("vulnerabilities", [])
        for item in sorted(vulns, key=lambda x: x.get("dateAdded", ""), reverse=True)[:5]:
            cve_id = item.get("cveID", "")
            item_hash = f"KEV_{cve_id}"
            
            vendor = item.get("vendorProject", "Unknown")
            product = item.get("product", "Unknown")
            date_added = item.get("dateAdded", datetime.now().strftime("%Y-%m-%d"))
            desc = item.get("shortDescription", "")
            action = item.get("requiredAction", "")
            link = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

            raw_title = f"CISA KEV: Active Exploitation of {vendor} {product} ({cve_id})"
            raw_desc = f"{desc} Required Action: {action}"
            
            if process_single_item(raw_title, date_added, raw_desc, link, item_hash, sent_cache):
                new_count += 1
    except Exception as e:
        print(f"[-] KEV check error: {e}", file=sys.stderr)
    return new_count

def check_rss_feed(feed_key, feed_url, sent_cache):
    new_count = 0
    data = fetch_url(feed_url)
    if not data:
        return new_count
    try:
        root = ET.fromstring(data)
        for item in root.findall(".//item")[:3]:
            title = sanitize_html(item.findtext("title", ""))
            link = item.findtext("link", "").strip()
            pub_date = item.findtext("pubDate", datetime.now().strftime("%Y-%m-%d"))
            desc = sanitize_html(item.findtext("description", ""))[:350]
            
            item_hash = hashlib.sha256(link.encode("utf-8")).hexdigest()
            
            if process_single_item(title, pub_date, desc, link, item_hash, sent_cache):
                new_count += 1
    except Exception as e:
        print(f"[-] RSS {feed_key} error: {e}", file=sys.stderr)
    return new_count

def main():
    print(f"[*] Starting Real-Time Threat Intel Scan at {datetime.now().isoformat()}...")
    sent_cache = load_sent_cache()
    total_new = 0

    # 1. Process CISA KEV
    total_new += check_cisa_kev(sent_cache)

    # 2. Process RSS Feeds sequentially
    for feed_key, feed_url in FEEDS.items():
        if feed_key == "cisa_kev":
            continue
        print(f"[*] Checking feed: {feed_key}...")
        total_new += check_rss_feed(feed_key, feed_url, sent_cache)

    print(f"[*] Scan complete. Delivered {total_new} new alerts.")

if __name__ == "__main__":
    main()
