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

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "8851782460:AAHjRPVhHzMoWDf3_DFsC-TPQz_UF-qu92s")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "-1004385697303")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")
ALERT_DELAY_SECONDS = int(os.getenv("ALERT_DELAY_SECONDS", "5"))
MAX_ALERTS_PER_RUN = int(os.getenv("MAX_ALERTS_PER_RUN", "3"))
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

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5"
}

# Cache the working model URL prefix once discovered
WORKING_MODEL_ENDPOINT = None

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

def format_for_telegram(text):
    """Normalizes AI output to clean, valid Telegram HTML."""
    if not text:
        return ""
    # Convert **bold** to <b>bold</b>
    cleaned = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
    # Convert markdown bullet points * or - to •
    cleaned = re.sub(r'^\s*[\*\-]\s+', '• ', cleaned, flags=re.MULTILINE)
    # Convert markdown headers ### to <b>
    cleaned = re.sub(r'^#{1,6}\s*(.*?)$', r'<b>\1</b>', cleaned, flags=re.MULTILINE)
    return cleaned.strip()

def send_telegram_alert(message_html):
    endpoint = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": format_for_telegram(message_html),
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

def call_gemini_api(api_key, prompt):
    """Calls Gemini API with automatic model & version fallback discovery."""
    global WORKING_MODEL_ENDPOINT
    
    # Candidate endpoints to try
    candidate_endpoints = []
    
    custom_model = os.getenv("GEMINI_MODEL")
    if custom_model:
        candidate_endpoints.append(f"https://generativelanguage.googleapis.com/v1beta/models/{custom_model}:generateContent")
        candidate_endpoints.append(f"https://generativelanguage.googleapis.com/v1/models/{custom_model}:generateContent")

    candidate_endpoints.extend([
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent",
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash:generateContent",
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.0-flash:generateContent",
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-pro:generateContent",
        "https://generativelanguage.googleapis.com/v1/models/gemini-3.6-flash:generateContent",
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent",
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent",
        "https://generativelanguage.googleapis.com/v1/models/gemini-1.5-flash:generateContent",
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent",
    ])

    # If we already discovered a working endpoint, put it first
    if WORKING_MODEL_ENDPOINT and WORKING_MODEL_ENDPOINT in candidate_endpoints:
        candidate_endpoints.remove(WORKING_MODEL_ENDPOINT)
        candidate_endpoints.insert(0, WORKING_MODEL_ENDPOINT)

    payload = {
        "contents": [{
            "parts": [{"text": prompt}]
        }],
        "generationConfig": {
            "temperature": 0.1,
            "maxOutputTokens": 800
        }
    }

    last_error = None
    for endpoint in candidate_endpoints:
        url = f"{endpoint}?key={api_key.strip()}"
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0",
                    "x-goog-api-key": api_key.strip()
                }
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                candidates = data.get("candidates", [])
                if not candidates:
                    continue
                parts = candidates[0].get("content", {}).get("parts", [])
                if not parts:
                    continue
                
                generated_text = parts[0].get("text", "")
                cleaned_text = re.sub(r'^```html\s*|^```markdown\s*|^```\s*|```$', '', generated_text.strip(), flags=re.MULTILINE).strip()
                WORKING_MODEL_ENDPOINT = endpoint
                print(f"[+] Gemini summary generated successfully via {endpoint.split('/models/')[1].split(':')[0]}!")
                return cleaned_text
        except urllib.error.HTTPError as e:
            error_msg = e.read().decode("utf-8")[:250]
            last_error = f"HTTP {e.code}: {error_msg}"
            print(f"[-] Endpoint {endpoint.split('/models/')[1].split(':')[0]} returned {last_error}", file=sys.stderr)
            continue
        except Exception as e:
            last_error = str(e)
            print(f"[-] Endpoint error: {last_error}", file=sys.stderr)
            continue

    print(f"[-] All Gemini endpoints failed. Last error: {last_error}", file=sys.stderr)
    return None

def generate_dynamic_alert(title, pub_date, desc, link):
    """Synthesizes CTI reports dynamically via Gemini API with robust prompt logic."""
    api_key = os.getenv("GEMINI_API_KEY")
    
    if not api_key:
        print("[!] CRITICAL ERROR: GEMINI_API_KEY environment variable is EMPTY or NOT SET!", file=sys.stderr)
    else:
        print(f"[*] GEMINI_API_KEY found: {api_key[:6]}... (Length: {len(api_key)})")
    
    fallback_alert = f"""🚨 <b>SOC Cyber Threat Intelligence Alert</b>

<b>Title:</b> {sanitize_html(title.strip())}
<b>Date:</b> {pub_date[:16]}
<b>Severity:</b> 🟠 High
<b>Category:</b> Vulnerability / Threat Intelligence
<b>Threat Actor:</b> Unspecified
<b>Affected Product/Organization:</b> Enterprise Software & Infrastructure
<b>CVE:</b> N/A

📝 <b>Summary:</b> 
{sanitize_html(desc.strip()[:350])}...

💥 <b>Impact:</b> 
Potential security risk, system compromise, or operational impact depending on deployment.

🔍 <b>IOCs:</b> 
See referenced advisory

🛡️ <b>Recommended Action:</b> 
• Review affected systems and apply vendor patches.
• Monitor logs and telemetry for anomalous activity.

🔗 <b>Source:</b> {link}"""

    if not api_key:
        print("[!] WARNING: GEMINI_API_KEY environment variable is NOT set. Using fallback template.", file=sys.stderr)
        return fallback_alert

    prompt = f"""You are a Senior Cyber Threat Intelligence Analyst.
Analyze and dynamically summarize this news item.

Title: {title}
Description: {desc}
URL: {link}

INSTRUCTIONS:
1. Determine if this item is an ACTIVE THREAT (Exploit/Malware/Ransomware) OR STRATEGIC GUIDANCE (Policy/Framework/Best Practice).
2. For Severity: Use 🔴 Critical / 🟠 High for active exploits or zero-days; 🟡 Medium for general vulnerabilities; 🟢 Low for framework/policy guidance.
3. For Threat Actor / CVE: Write 'N/A' or 'Strategic Guidance' if none are mentioned.
4. For Recommended Action: Tailor actions specifically to the article (e.g., if it's logging guidance, suggest architecture review rather than patching).

Generate the response using HTML tags following this EXACT template:

🚨 <b>SOC Cyber Threat Intelligence Alert</b>

<b>Title:</b> [Synthesize a clear, threat or policy-focused professional title]
<b>Date:</b> {pub_date[:16]}
<b>Severity:</b> [🔴 Critical / 🟠 High / 🟡 Medium / 🟢 Low]
<b>Category:</b> [e.g., Policy / Logging Architecture, Vulnerability, Malware, APT, Ransomware]
<b>Threat Actor:</b> [APT group name if mentioned, otherwise "Unknown / Unspecified" or "N/A"]
<b>Affected Product/Organization:</b> [Target software, vendor, or sector, e.g., "Enterprise Logging Systems / Federal Agencies"]
<b>CVE:</b> [CVE ID(s) if mentioned, otherwise "N/A"]

📝 <b>Summary:</b> 
[2–3 concise sentences summarizing what happened, key takeaways, and why it matters]

💥 <b>Impact:</b> 
[Direct technical, operational, or strategic risk]

🔍 <b>IOCs:</b> 
[Hashes, IP ranges, or "N/A (Strategic Guidance)"]

🛡️ <b>Recommended Action:</b> 
• [Tailored action step 1]
• [Tailored action step 2]

🔗 <b>Source:</b> {link}

Return raw HTML only. Do NOT output markdown code blocks like ```html or ```."""

    ai_result = call_gemini_api(api_key, prompt)
    if ai_result:
        return ai_result
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
        # 3. Pause before moving to the next item
        time.sleep(ALERT_DELAY_SECONDS)
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

def sanitize_xml(xml_bytes):
    """Sanitizes raw XML by fixing unescaped ampersands and malformed characters."""
    try:
        text = xml_bytes.decode("utf-8", errors="replace")
        # Replace unescaped & with &amp;
        cleaned = re.sub(r'&(?!amp;|lt;|gt;|quot;|apos;|#\d+;|#x[0-9a-fA-F]+;)', '&amp;', text)
        return cleaned.encode("utf-8")
    except Exception:
        return xml_bytes

def check_rss_feed(feed_key, feed_url, sent_cache):
    new_count = 0
    data = fetch_url(feed_url)
    if not data:
        return new_count
    try:
        clean_xml = sanitize_xml(data)
        root = ET.fromstring(clean_xml)
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
    if total_new >= MAX_ALERTS_PER_RUN:
        print(f"[*] Reached batch limit of {MAX_ALERTS_PER_RUN} alerts. Finishing run.")
        print(f"[*] Scan complete. Delivered {total_new} new alerts.")
        return

    # 2. Process RSS Feeds sequentially
    for feed_key, feed_url in FEEDS.items():
        if feed_key == "cisa_kev":
            continue
        print(f"[*] Checking feed: {feed_key}...")
        total_new += check_rss_feed(feed_key, feed_url, sent_cache)
        if total_new >= MAX_ALERTS_PER_RUN:
            print(f"[*] Reached batch limit of {MAX_ALERTS_PER_RUN} alerts. Finishing run.")
            break

    print(f"[*] Scan complete. Delivered {total_new} new alerts.")

if __name__ == "__main__":
    main()
