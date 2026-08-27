#!/usr/bin/env python3
"""
GDPFMIT SOC Unified Threat Intelligence Engine
- Real-Time Mode: Fetches feeds, filters for vendors, deduplicates, and sends photo alerts to Telegram.
- Briefing Mode: Generates Top 5 Executive Threat Briefings (Morning 8:00 AM & Evening 5:30 PM ICT).
Includes automatic 503/429 retry backoff and zero-downtime briefing fallback.
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
ALERT_DELAY_SECONDS = int(os.getenv("ALERT_DELAY_SECONDS", "15"))
MAX_ALERTS_PER_RUN = int(os.getenv("MAX_ALERTS_PER_RUN", "3"))
BRIEFING_MODE = os.getenv("BRIEFING_MODE", "").lower()
STATE_FILE = "sent_alerts.json"

if not BOT_TOKEN or not CHAT_ID:
    sys.exit("[-] Error: TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID environment variables must be set.")

FEEDS = {
    "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "the_hacker_news": "https://feeds.feedburner.com/TheHackersNews",
    "bleeping_computer": "https://www.bleepingcomputer.com/feed/",
    "cybersecurity_news": "https://cybersecuritynews.com/feed/",
    "securityweek": "https://www.securityweek.com/feed/",
    "vulncheck": "https://www.vulncheck.com/blog",
    "gbhackers": "https://gbhackers.com/feed/",
    "sc_magazine": "https://www.scworld.com/feed/",
    "help_net_security": "https://www.helpnetsecurity.com/feed/",
    "ipurple_team": "https://ipurple.team/feed/",
    "infosecurity_magazine": "https://www.infosecurity-magazine.com/rss/news/",
    "ciso_series": "https://cisoseries.com/feed/",
    "security_boulevard": "https://securityboulevard.com/feed/"
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9"
}

TRACKED_VENDORS = [
    "ibm", "microsoft", "windows", "azure", "office 365", "m365", "exchange", "active directory",
    "sharepoint", "palo alto", "pan-os", "globalprotect", "cortex", "fortinet", "fortios", "fortigate",
    "f5", "big-ip", "cisco", "anyconnect", "catalyst", "ios-xe", "crowdstrike", "falcon",
    "sentinelone", "splunk", "elastic", "elasticsearch", "kibana", "google", "gcp", "workspace",
    "chrome", "tenable", "nessus", "qualys", "rapid7", "insightvm", "metasploit", "cyberark",
    "okta", "proofpoint", "cloudflare", "zscaler", "check point", "sophos", "trellix",
    "mandiant", "recorded future", "wiz", "servicenow", "manageengine", "zoho", "veeam",
    "oracle", "weblogic", "netbackup", "veritas", "spring", "vmware", "vcenter", "esxi",
    "apache", "linux", "confluence", "jira", "atlassian", "ivanti", "sonicwall"
]

MALWARE_TOPICS = [
    "malware", "ransomware", "zero-day", "0-day", "cve-", "exploit", "trojan",
    "stealer", "infostealer", "backdoor", "apt", "threat actor", "botnet",
    "phishing campaign", "data breach", "supply chain", "rce", "privilege escalation",
    "authentication bypass", "arbitrary code execution", "active exploitation"
]

def is_relevant_threat(title, desc):
    combined = f"{title} {desc}".lower()
    for vendor in TRACKED_VENDORS:
        if vendor in combined:
            return True
    for topic in MALWARE_TOPICS:
        if topic in combined:
            return True
    return False

WORKING_MODEL_ENDPOINT = None

def sanitize_html(text):
    if not text:
        return ""
    clean = re.sub(r'<[^>]+>', '', text)
    return html.escape(html.unescape(clean)).strip()

def format_for_telegram(text):
    if not text:
        return ""
    cleaned = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
    cleaned = re.sub(r'`(.*?)`', r'<code>\1</code>', cleaned)
    cleaned = re.sub(r'^\s*[\*\-]\s+', '• ', cleaned, flags=re.MULTILINE)
    cleaned = re.sub(r'^#{1,6}\s*(.*?)$', r'<b>\1</b>', cleaned, flags=re.MULTILINE)
    return cleaned.strip()

def normalize_url(url):
    if not url:
        return ""
    clean = re.sub(r'(\?|#).*$', '', url.strip())
    return clean.rstrip('/')

def extract_cve_ids(text):
    if not text:
        return []
    return re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)

def create_title_slug(title):
    if not title:
        return ""
    clean = re.sub(r'[^\w\s]', '', title.lower())
    stopwords = {"a", "an", "the", "in", "on", "at", "for", "to", "of", "and", "or", "is", "are", "with", "by", "as", "flaw", "flaws", "alert"}
    words = [w for w in clean.split() if w not in stopwords]
    return "slug_" + "_".join(words[:6])

def check_is_duplicate(title, desc, link, sent_cache):
    norm_link = normalize_url(link)
    link_hash = hashlib.sha256(norm_link.encode("utf-8")).hexdigest()
    
    if link_hash in sent_cache or norm_link in sent_cache:
        return True, []

    cves = extract_cve_ids(f"{title} {desc}")
    for cve in cves:
        cve_key = f"CVE_{cve.upper()}"
        if cve_key in sent_cache:
            print(f"[*] Skipping duplicate item (Already alerted on {cve}): {title[:40]}...")
            return True, []

    slug_key = create_title_slug(title)
    if slug_key and slug_key in sent_cache:
        print(f"[*] Skipping duplicate item (Matching title slug): {title[:40]}...")
        return True, []

    fingerprints = [link_hash, norm_link]
    if slug_key:
        fingerprints.append(slug_key)
    for cve in cves:
        fingerprints.append(f"CVE_{cve.upper()}")

    return False, fingerprints

def load_sent_cache():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
        except Exception as e:
            return []
    return []

def save_sent_cache(sent_list):
    try:
        trimmed = sent_list[-1000:]
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
        with urllib.request.urlopen(req, timeout=25) as resp:
            return resp.read()
    except Exception as e:
        return None

def extract_image_url(item, raw_desc, link):
    if item is not None:
        enclosure = item.find("enclosure")
        if enclosure is not None:
            url = enclosure.get("url")
            if url and any(url.lower().endswith(ext) for ext in [".jpg", ".jpeg", ".png", ".webp"]):
                return url

        for child in item:
            tag_lower = child.tag.lower()
            if "content" in tag_lower or "thumbnail" in tag_lower:
                url = child.get("url")
                if url and any(url.lower().endswith(ext) for ext in [".jpg", ".jpeg", ".png", ".webp"]):
                    return url

    if raw_desc:
        img_match = re.search(r'<img[^>]+src=["\'](https?://[^"\']+\.(?:jpg|jpeg|png|webp)[^"\']*)["\']', raw_desc, re.IGNORECASE)
        if img_match:
            return img_match.group(1)

    if link and link.startswith("http"):
        try:
            page_data = fetch_url(link)
            if page_data:
                html_text = page_data.decode("utf-8", errors="ignore")
                og_match = re.search(r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\'](https?://[^"\']+)["\']', html_text, re.IGNORECASE)
                if not og_match:
                    og_match = re.search(r'<meta[^>]+content=["\'](https?://[^"\']+)["\'][^>]+property=["\']og:image["\']', html_text, re.IGNORECASE)
                if og_match:
                    return og_match.group(1)
        except Exception:
            pass

    return None

def send_telegram_alert(message_html, image_url=None):
    formatted_text = format_for_telegram(message_html)
    
    if image_url:
        endpoint = f"https://api.telegram.org/bot{BOT_TOKEN}/sendPhoto"
        payload = {
            "chat_id": CHAT_ID,
            "photo": image_url,
            "caption": formatted_text,
            "parse_mode": "HTML"
        }
        req = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": HEADERS["User-Agent"]}
        )
        try:
            with urllib.request.urlopen(req, timeout=25) as resp:
                res = json.loads(resp.read().decode("utf-8"))
                if res.get("ok", False):
                    print(f"[+] Photo alert dispatched successfully with image: {image_url[:40]}...")
                    return True
        except Exception as e:
            print(f"[-] sendPhoto failed ({e}), falling back to sendMessage...", file=sys.stderr)

    endpoint = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": formatted_text,
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
    """Calls Gemini API with exponential retry backoff on 429 and 503 errors."""
    global WORKING_MODEL_ENDPOINT
    
    candidate_endpoints = [
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent",
        "https://generativelanguage.googleapis.com/v1/models/gemini-3.6-flash:generateContent",
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
    ]

    if WORKING_MODEL_ENDPOINT and WORKING_MODEL_ENDPOINT in candidate_endpoints:
        candidate_endpoints.remove(WORKING_MODEL_ENDPOINT)
        candidate_endpoints.insert(0, WORKING_MODEL_ENDPOINT)

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.1, "maxOutputTokens": 4096}
    }

    last_error = None
    for endpoint in candidate_endpoints:
        url = f"{endpoint}?key={api_key.strip()}"
        for attempt in range(3):
            try:
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json", "x-goog-api-key": api_key.strip()}
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    candidates = data.get("candidates", [])
                    if not candidates:
                        continue
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if not parts:
                        continue
                    
                    text_parts = [p.get("text", "") for p in parts if "text" in p]
                    generated_text = "".join(text_parts)
                    cleaned_text = re.sub(r'^```html\s*|^```markdown\s*|^```\s*|```$', '', generated_text.strip(), flags=re.MULTILINE).strip()
                    WORKING_MODEL_ENDPOINT = endpoint
                    print(f"[+] Gemini summary generated successfully via {endpoint.split('/models/')[1].split(':')[0]}!")
                    return cleaned_text
            except urllib.error.HTTPError as e:
                error_msg = e.read().decode("utf-8")[:250]
                last_error = f"HTTP {e.code}: {error_msg}"
                if e.code in [429, 503]:
                    wait_time = (attempt + 1) * 8
                    print(f"[-] API returned {e.code} (High Demand/Rate Limit). Backing off {wait_time}s (Attempt {attempt+1}/3)...", file=sys.stderr)
                    time.sleep(wait_time)
                    continue
                print(f"[-] Endpoint {endpoint.split('/models/')[1].split(':')[0]} returned {last_error}", file=sys.stderr)
                break
            except Exception as e:
                last_error = str(e)
                print(f"[-] Endpoint error: {last_error}", file=sys.stderr)
                break

    print(f"[-] All Gemini endpoints failed. Last error: {last_error}", file=sys.stderr)
    return None

def generate_dynamic_alert(title, pub_date, desc, link):
    api_key = os.getenv("GEMINI_API_KEY")
    
    fallback_alert = f"""<a href="{link}"><b>{sanitize_html(title.strip())}</b></a>

{sanitize_html(desc.strip()[:300])}... Organizations using the affected software are advised to review systems and apply the latest security updates.

FMIS | OIS - SOC TEAM"""

    if not api_key:
        return fallback_alert

    prompt = f"""You are a Cyber Threat Intelligence Specialist writing a clean, professional threat news post.
Analyze this cybersecurity news item:

Title: {title}
Description: {desc}
URL: {link}

INSTRUCTIONS:
1. First line MUST be a bold clickable hyperlink of the title leading to the URL using the exact format: <a href="{link}"><b>[Synthesized Threat News Title]</b></a>
2. In the body paragraph, write a brief, high-impact summary of the threat news in 2–4 lines covering:
   - What happened
   - Who/what is affected (software, vendor, or organization)
   - The main threat, vulnerability (CVE ID if any), malware, or attack technique
   - Important security recommendation (patching, configuration, or monitoring)
3. The footer MUST be: FMIS | OIS - SOC TEAM

Generate the response following this EXACT structure:

<a href="{link}"><b>[Threat News Title]</b></a>

[2–4 lines concise summary highlighting what happened, affected products, the key vulnerability/technique, and security recommendations.]

FMIS | OIS - SOC TEAM

Return raw text with HTML tags only. Do NOT output markdown code blocks."""

    ai_result = call_gemini_api(api_key, prompt)
    if ai_result:
        return ai_result
    return fallback_alert

def process_single_item(title, pub_date, desc, link, sent_cache, image_url=None):
    is_dup, fingerprints = check_is_duplicate(title, desc, link, sent_cache)
    if is_dup:
        return False

    print(f"[>] Generating AI summary for: {title[:50]}...")
    alert_text = generate_dynamic_alert(title, pub_date, desc, link)
    
    print(f"[+] Sending alert to Telegram for: {title[:40]}...")
    if send_telegram_alert(alert_text, image_url=image_url):
        for key in fingerprints:
            if key and key not in sent_cache:
                sent_cache.append(key)
        save_sent_cache(sent_cache)
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
            if new_count >= 1:
                break
            cve_id = item.get("cveID", "")
            vendor = item.get("vendorProject", "Unknown")
            product = item.get("product", "Unknown")
            date_added = item.get("dateAdded", datetime.now().strftime("%Y-%m-%d"))
            desc = item.get("shortDescription", "")
            action = item.get("requiredAction", "")
            link = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog#{cve_id}"

            raw_title = f"Active Exploitation of {vendor} {product} ({cve_id})"
            raw_desc = f"{desc} Required Action: {action}"
            
            if process_single_item(raw_title, date_added, raw_desc, link, sent_cache):
                new_count += 1
    except Exception as e:
        print(f"[-] KEV check error: {e}", file=sys.stderr)
    return new_count

def check_vulncheck_source(sent_cache):
    new_count = 0
    page_html = fetch_url(FEEDS["vulncheck"])
    if not page_html:
        return new_count
    try:
        text = page_html.decode("utf-8", errors="ignore")
        articles = re.findall(r'<a[^>]+href=["\'](/blog/[^"\']+)["\'][^>]*>(.*?)</a>', text, re.DOTALL)
        seen_links = set()
        for rel_link, raw_content in articles:
            if new_count >= 1:
                break
            full_link = f"https://www.vulncheck.com{rel_link}"
            if full_link in seen_links or rel_link == "/blog":
                continue
            seen_links.add(full_link)
            
            title = sanitize_html(raw_content)
            if not title or len(title) < 10:
                continue

            pub_date = datetime.now().strftime("%Y-%m-%d")
            desc = f"VulnCheck Research Advisory: {title}"

            if not is_relevant_threat(title, desc):
                continue

            image_url = extract_image_url(None, None, full_link)
            if process_single_item(title, pub_date, desc, full_link, sent_cache, image_url=image_url):
                new_count += 1
    except Exception as e:
        print(f"[-] VulnCheck processing error: {e}", file=sys.stderr)
    return new_count

def sanitize_xml(xml_bytes):
    try:
        text = xml_bytes.decode("utf-8", errors="replace")
        cleaned = re.sub(r'&(?!amp;|lt;|gt;|quot;|apos;|#\d+;|#x[0-9a-fA-F]+;)', '&amp;', text)
        return cleaned.encode("utf-8")
    except Exception:
        return xml_bytes

def check_rss_feed(feed_key, feed_url, sent_cache, current_total):
    new_count = 0
    data = fetch_url(feed_url)
    if not data:
        return new_count
    try:
        clean_xml = sanitize_xml(data)
        root = ET.fromstring(clean_xml)
        for item in root.findall(".//item")[:8]:
            if current_total + new_count >= MAX_ALERTS_PER_RUN or new_count >= 1:
                break
            title = sanitize_html(item.findtext("title", ""))
            link = item.findtext("link", "").strip()
            pub_date = item.findtext("pubDate", datetime.now().strftime("%Y-%m-%d"))
            raw_desc = item.findtext("description", "") or ""
            desc = sanitize_html(raw_desc)[:400]
            
            if not is_relevant_threat(title, desc):
                continue

            image_url = extract_image_url(item, raw_desc, link)
            if process_single_item(title, pub_date, desc, link, sent_cache, image_url=image_url):
                new_count += 1
    except Exception as e:
        print(f"[-] RSS {feed_key} error: {e}", file=sys.stderr)
    return new_count

# ─────────────────────────────────────────────────────────────
# 🌟 TOP 5 EXECUTIVE BRIEFING ENGINE (Morning & Evening)
# ─────────────────────────────────────────────────────────────

def collect_top_threats_for_briefing():
    """Aggregates all fresh threat items from CISA, VulnCheck, and RSS for the briefing."""
    items = []
    # 1. CISA KEV
    cisa_data = fetch_url(FEEDS["cisa_kev"])
    if cisa_data:
        try:
            payload = json.loads(cisa_data.decode("utf-8"))
            for v in payload.get("vulnerabilities", [])[:5]:
                cve = v.get("cveID", "")
                vendor = v.get("vendorProject", "")
                prod = v.get("product", "")
                desc = v.get("shortDescription", "")
                items.append({
                    "title": f"Active Exploitation of {vendor} {prod} ({cve})",
                    "desc": desc,
                    "link": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog#{cve}"
                })
        except Exception:
            pass

    # 2. Key Feeds
    for feed_key in ["the_hacker_news", "bleeping_computer", "cybersecurity_news", "gbhackers", "securityweek"]:
        data = fetch_url(FEEDS[feed_key])
        if not data:
            continue
        try:
            clean_xml = sanitize_xml(data)
            root = ET.fromstring(clean_xml)
            for entry in root.findall(".//item")[:4]:
                t = sanitize_html(entry.findtext("title", ""))
                l = entry.findtext("link", "").strip()
                d = sanitize_html(entry.findtext("description", "") or "")[:350]
                if t and l and is_relevant_threat(t, d):
                    items.append({"title": t, "link": l, "desc": d})
        except Exception:
            pass

    return items[:18]

def build_fallback_briefing(threats, edition_label, today_str):
    """Zero-downtime fallback briefing when Google AI has temporary service outages."""
    numbers = ["1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣"]
    items_html = []
    for i, t in enumerate(threats[:5]):
        num_emoji = numbers[i] if i < len(numbers) else f"{i+1}️⃣"
        items_html.append(f"""{num_emoji} <a href="{t['link']}"><b>{t['title']}</b></a>
⚡ <b>Severity:</b> 🔴 Critical | 🏷️ <b>Category:</b> Security Advisory
📝 {t['desc'][:220]}...""")

    items_block = "\n\n".join(items_html)
    return f"""🛡️ <b>GDPFMIT SOC Daily Threat Briefing — {edition_label}</b>
📅 <b>Date:</b> {today_str} · {edition_label} ICT
🔒 <b>Overall Threat Level:</b> 🔴 Elevated

━━━━━━━━━━━━━━━━━━━━
📌 <b>TOP 5 CYBERSECURITY THREATS & INCIDENTS</b>
━━━━━━━━━━━━━━━━━━━━

{items_block}

━━━━━━━━━━━━━━━━━━━━
🛡️ <b>KEY SOC ACTIONS</b>
• Audit exposed enterprise assets for reported CVEs and vulnerabilities.
• Review perimeter firewall logs and correlate authentication telemetry.
• Ensure vendor security patches and mitigations are applied promptly.
━━━━━━━━━━━━━━━━━━━━
FMIS | OIS - SOC TEAM"""

def run_executive_briefing(edition_label):
    """Generates and delivers the Top 5 Executive Threat Briefing to Telegram."""
    api_key = os.getenv("GEMINI_API_KEY")
    print(f"[*] Generating Top 5 Executive Briefing ({edition_label})...")
    threats = collect_top_threats_for_briefing()
    today_str = datetime.now().strftime("%Y-%m-%d")

    briefing_html = None
    if api_key:
        threat_text = "\n".join([f"- Title: {x['title']}\n  Link: {x['link']}\n  Desc: {x['desc']}" for x in threats])
        prompt = f"""You are a Senior Cyber Threat Intelligence Lead.
Create an executive 'TOP 5 CYBERSECURITY THREAT BRIEFING' for leadership and the SOC team.

Edition: {edition_label}
Date: {today_str}

Available news items:
{threat_text}

INSTRUCTIONS:
1. Select the top 5 most critical/impactful threat items (prioritize Microsoft, Palo Alto, Cisco, Oracle, VMware, Fortinet, Veeam, Zero-days, Ransomware).
2. For each of the 5 items, output:
   - Numbered title as clickable HTML hyperlink: <a href="URL"><b>[Title]</b></a>
   - Severity and Threat Category (🔴 Critical / 🟠 High / 🟡 Medium)
   - 1-2 sentence plain-language technical summary.
3. Add a concise 'KEY SOC ACTIONS' section with 2-3 specific bullet points.
4. End with footer: FMIS | OIS - SOC TEAM

OUTPUT HTML STRUCTURE:
🛡️ <b>GDPFMIT SOC Daily Threat Briefing — {edition_label}</b>
📅 <b>Date:</b> {today_str} · {edition_label} ICT
🔒 <b>Overall Threat Level:</b> [🔴 Elevated / 🟠 Moderate / 🟢 Normal]

━━━━━━━━━━━━━━━━━━━━
📌 <b>TOP 5 CYBERSECURITY THREATS & INCIDENTS</b>
━━━━━━━━━━━━━━━━━━━━

1️⃣ <a href="[URL]"><b>[Title 1]</b></a>
⚡ <b>Severity:</b> [🔴 Critical / 🟠 High] | 🏷️ <b>Category:</b> [Category]
📝 [1-2 sentence executive summary]

2️⃣ <a href="[URL]"><b>[Title 2]</b></a>
⚡ <b>Severity:</b> [🔴 Critical / 🟠 High] | 🏷️ <b>Category:</b> [Category]
📝 [1-2 sentence executive summary]

3️⃣ <a href="[URL]"><b>[Title 3]</b></a>
⚡ <b>Severity:</b> [🔴 Critical / 🟠 High / 🟡 Medium] | 🏷️ <b>Category:</b> [Category]
📝 [1-2 sentence executive summary]

4️⃣ <a href="[URL]"><b>[Title 4]</b></a>
⚡ <b>Severity:</b> [🟠 High / 🟡 Medium] | 🏷️ <b>Category:</b> [Category]
📝 [1-2 sentence executive summary]

5️⃣ <a href="[URL]"><b>[Title 5]</b></a>
⚡ <b>Severity:</b> [🟡 Medium / 🟢 Low] | 🏷️ <b>Category:</b> [Category]
📝 [1-2 sentence executive summary]

━━━━━━━━━━━━━━━━━━━━
🛡️ <b>KEY SOC ACTIONS</b>
• [Specific SOC Action 1]
• [Specific SOC Action 2]
━━━━━━━━━━━━━━━━━━━━
FMIS | OIS - SOC TEAM

Return clean HTML only. Do NOT include markdown blocks."""
        briefing_html = call_gemini_api(api_key, prompt)

    if not briefing_html:
        print("[!] Using automated zero-downtime fallback briefing generator...")
        briefing_html = build_fallback_briefing(threats, edition_label, today_str)

    endpoint = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": format_for_telegram(briefing_html),
        "parse_mode": "HTML",
        "link_preview_options": {"is_disabled": True}
    }
    req = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            res = json.loads(resp.read().decode("utf-8"))
            if res.get("ok", False):
                print(f"[+] Successfully delivered {edition_label} Briefing to Telegram!")
                return True
    except Exception as e:
        print(f"[-] Telegram dispatch error for briefing: {e}", file=sys.stderr)
    return False

def main():
    mode = BRIEFING_MODE
    if len(sys.argv) > 1 and sys.argv[1].startswith("--briefing"):
        mode = sys.argv[2].lower() if len(sys.argv) > 2 else "morning"

    if mode in ["morning", "morning ☀️", "8:00 am"]:
        run_executive_briefing("Morning ☀️ (8:00 AM)")
        return
    elif mode in ["evening", "evening 🌙", "5:30 pm"]:
        run_executive_briefing("Evening 🌙 (5:30 PM)")
        return

    # Real-Time Scan
    print(f"[*] Starting Real-Time Threat Intel Scan at {datetime.now().isoformat()}...")
    sent_cache = load_sent_cache()
    total_new = 0

    total_new += check_cisa_kev(sent_cache)

    for feed_key, feed_url in FEEDS.items():
        if feed_key == "cisa_kev":
            continue
        if total_new >= MAX_ALERTS_PER_RUN:
            print(f"[*] Reached batch limit of {MAX_ALERTS_PER_RUN} alerts. Finishing run.")
            break
        print(f"[*] Checking feed: {feed_key} ({feed_url})...")
        if feed_key == "vulncheck":
            total_new += check_vulncheck_source(sent_cache)
        else:
            total_new += check_rss_feed(feed_key, feed_url, sent_cache, total_new)

    print(f"[*] Scan complete. Delivered {total_new} new alerts.")

if __name__ == "__main__":
    main()
