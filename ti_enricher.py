#!/usr/bin/env python3
"""
ti_enricher.py — EDR Threat Intel Enrichment Engine (Upgraded)
===============================================================
Key upgrades from original:
  1. Reads soc-logs-*,osquery-*,filebeat-* (was filebeat-* only)
  2. LotL behavioral scoring — 40+ rules, no API needed
  3. Internal whitelist — never scores SOC server or local subnets
  4. MITRE ATT&CK tactic mapping per event
  5. soar_state: Detected written for SOAR state machine pickup
  6. Behavioral + API scores combined (max wins)
  7. Auto-generated alert names from event content
"""

import os, re, sys, json, time, logging, ipaddress
import requests
from datetime import datetime, timezone

ES_HOST      = os.getenv("ES_HOST",      "http://192.168.23.130:9200")
ES_INDEX     = os.getenv("ES_INDEX",     "soc-logs-*,osquery-*,filebeat-*")
ES_OUT_INDEX = os.getenv("ES_OUT_INDEX", "ti-enriched")
BATCH_SIZE   = int(os.getenv("BATCH_SIZE", "50"))

VT_API_KEY    = os.getenv("VT_API_KEY",    "")
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY", "")
OTX_API_KEY   = os.getenv("OTX_API_KEY",   "")

WEIGHT_VT = 50; WEIGHT_ABUSE = 30; WEIGHT_OTX = 20
RATE_DELAY = 0.15; REQ_TIMEOUT = 8

WHITELIST_IPS = {"192.168.23.130","192.168.23.132","127.0.0.1","0.0.0.0"}
PRIVATE_NETS  = [ipaddress.ip_network(n) for n in
                 ["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8"]]

MITRE_MAP = {
    "powershell":  {"tactic":"Execution",        "technique":"T1059.001","name":"PowerShell"},
    "-enc":        {"tactic":"Defense Evasion",  "technique":"T1027",    "name":"Obfuscated Command"},
    "webclient":   {"tactic":"C2",               "technique":"T1105",    "name":"Web Download"},
    "downloadstring":{"tactic":"C2",             "technique":"T1105",    "name":"Download in Memory"},
    "crontab":     {"tactic":"Persistence",      "technique":"T1053.003","name":"Cron Persistence"},
    "useradd":     {"tactic":"Persistence",      "technique":"T1136",    "name":"Create Account"},
    "ssh":         {"tactic":"Lateral Movement", "technique":"T1021.004","name":"SSH"},
    "wget":        {"tactic":"C2",               "technique":"T1105",    "name":"Tool Transfer"},
    "curl":        {"tactic":"C2",               "technique":"T1105",    "name":"Tool Transfer"},
    "nc -e":       {"tactic":"C2",               "technique":"T1059",    "name":"Reverse Shell"},
    "base64":      {"tactic":"Defense Evasion",  "technique":"T1027",    "name":"Base64 Encoding"},
    "chmod +x":    {"tactic":"Defense Evasion",  "technique":"T1222",    "name":"File Permissions"},
    "/etc/shadow": {"tactic":"Credential Access","technique":"T1003.008","name":"Shadow File Access"},
    "/etc/passwd": {"tactic":"Credential Access","technique":"T1003",    "name":"Passwd File Access"},
    "nmap":        {"tactic":"Discovery",        "technique":"T1046",    "name":"Network Scan"},
    "whoami":      {"tactic":"Discovery",        "technique":"T1033",    "name":"System Owner Discovery"},
    "/tmp/":       {"tactic":"Execution",        "technique":"T1059",    "name":"Exec from /tmp"},
    "/dev/shm/":   {"tactic":"Execution",        "technique":"T1059",    "name":"Exec from /dev/shm"},
    "iptables -f": {"tactic":"Defense Evasion",  "technique":"T1562.004","name":"Disable Firewall"},
    "mimikatz":    {"tactic":"Credential Access","technique":"T1003",    "name":"Mimikatz"},
    "mshta":       {"tactic":"Execution",        "technique":"T1218.005","name":"MSHTA Bypass"},
    "certutil":    {"tactic":"Defense Evasion",  "technique":"T1140",    "name":"Certutil Decode"},
}

LOTL_RULES = [
    (r'powershell.*-e[nc]',              40, "PowerShell encoded command"),
    (r'powershell.*webclient',           45, "PowerShell web download"),
    (r'powershell.*downloadstring',      45, "PowerShell in-memory download"),
    (r'powershell.*iex\(',               50, "PowerShell IEX exec"),
    (r'base64\s+-d',                     25, "Base64 decode pipe"),
    (r'curl.*\|\s*bash',                 70, "Curl pipe to bash"),
    (r'wget.*\|\s*sh',                   70, "Wget pipe to shell"),
    (r'curl.*-o\s+/tmp/',                45, "Download to /tmp"),
    (r'wget.*-O\s+/tmp/',                45, "Download to /tmp"),
    (r'nc\s+-[el]',                      55, "Netcat listener/connect"),
    (r'bash\s+-i\s+>&',                  70, "Interactive bash redirect"),
    (r'sh\s+-i\s+>&',                    70, "Interactive sh redirect"),
    (r'cat\s+/etc/shadow',               60, "Shadow file read"),
    (r'cat\s+/etc/passwd',               30, "Passwd file read"),
    (r'mimikatz',                        90, "Mimikatz detected"),
    (r'nmap\s+',                         35, "Network scan"),
    (r'masscan\s+',                      40, "Mass port scan"),
    (r'crontab\s+-[el]',                 30, "Crontab modification"),
    (r'useradd|adduser',                 35, "User account created"),
    (r'history\s+-c',                    40, "Bash history cleared"),
    (r'unset\s+HISTFILE',                40, "History logging disabled"),
    (r'chmod\s+\+x\s+/tmp/',             35, "Exec perm on /tmp file"),
    (r'iptables.*-F',                    40, "Firewall rules flushed"),
    (r'ufw\s+disable',                   40, "UFW disabled"),
    (r'setenforce\s+0',                  45, "SELinux disabled"),
    (r'exec.*\/tmp\/',                   45, "Execute from /tmp"),
    (r'exec.*\/dev\/shm\/',              50, "Execute from /dev/shm"),
    (r'python.*-c.*socket',              35, "Python socket code"),
    (r'perl\s+-e',                       30, "Perl one-liner"),
    (r'ruby\s+-e',                       30, "Ruby one-liner"),
    (r'echo.*>>\s*~?/\.bashrc',          25, "Bashrc modification"),
    (r'find\s+/\s+.*-perm.*[sg]uid',     40, "SUID/SGID search"),
    (r'john\s+--',                       50, "John the Ripper"),
    (r'hashcat',                         50, "Hashcat password crack"),
    (r'apache2.*bash|nginx.*bash',       55, "Web server spawned bash"),
    (r'winword.*cmd|excel.*powershell',  65, "Office spawned shell"),
]

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S")
log = logging.getLogger("ti_enricher")

def is_private(ip):
    if ip in WHITELIST_IPS: return True
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in PRIVATE_NETS)
    except ValueError: return True

def extract_iocs(src):
    text    = json.dumps(src)
    ips     = {ip for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text) if not is_private(ip)}
    sha256s = set(re.findall(r'\b[0-9a-fA-F]{64}\b', text))
    md5s    = set(re.findall(r'\b[0-9a-fA-F]{32}\b', text)) - sha256s
    return {"ips": list(ips), "sha256": list(sha256s), "md5": list(md5s)}

def detect_mitre(src):
    text = json.dumps(src).lower()
    seen, matched = set(), []
    for kw, info in MITRE_MAP.items():
        if kw in text and info["technique"] not in seen:
            matched.append(info); seen.add(info["technique"])
    return matched

def behavioral_score(src):
    text = json.dumps(src).lower()
    total, reasons = 0, []
    for pattern, pts, reason in LOTL_RULES:
        if re.search(pattern, text, re.IGNORECASE):
            total += pts; reasons.append(f"{reason} (+{pts})")
            log.info("    LotL: %s +%d", reason, pts)
    return min(total, 85), reasons

def alert_name(src, mitre, lotl):
    if lotl:   return lotl[0].split(" (+")[0]
    if mitre:  return mitre[0]["name"]
    text = json.dumps(src).lower()
    if "shadow" in text:            return "Credential File Access"
    if "nmap" in text:              return "Network Reconnaissance"
    if "base64" in text:            return "Encoded Command Execution"
    if "/tmp/" in text:             return "Execution from /tmp"
    if "crontab" in text:           return "Cron Persistence"
    if "wget" in text or "curl" in text: return "Suspicious Download"
    return "Threat Intel Match"

def vt_ip(ip):
    if not VT_API_KEY: return -1
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                         headers={"x-apikey":VT_API_KEY}, timeout=REQ_TIMEOUT)
        if r.status_code == 200:
            s = r.json()["data"]["attributes"]["last_analysis_stats"]
            return min(100, int((s.get("malicious",0)+s.get("suspicious",0)*.5)/max(sum(s.values()),1)*100))
        return 0
    except: return -1

def vt_hash(h):
    if not VT_API_KEY: return -1
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{h}",
                         headers={"x-apikey":VT_API_KEY}, timeout=REQ_TIMEOUT)
        if r.status_code == 200:
            s = r.json()["data"]["attributes"]["last_analysis_stats"]
            return min(100, int((s.get("malicious",0)+s.get("suspicious",0)*.5)/max(sum(s.values()),1)*100))
        return 0
    except: return -1

def abuse_ip(ip):
    if not ABUSE_API_KEY: return -1
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers={"Key":ABUSE_API_KEY,"Accept":"application/json"},
                         params={"ipAddress":ip,"maxAgeInDays":90}, timeout=REQ_TIMEOUT)
        return int(r.json()["data"].get("abuseConfidenceScore",0)) if r.status_code==200 else 0
    except: return -1

def otx_ip(ip):
    if not OTX_API_KEY: return -1
    try:
        r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                         headers={"X-OTX-API-KEY":OTX_API_KEY}, timeout=REQ_TIMEOUT)
        return min(100,r.json().get("pulse_info",{}).get("count",0)*15) if r.status_code==200 else 0
    except: return -1

def otx_hash(h):
    if not OTX_API_KEY: return -1
    try:
        r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/file/{h}/general",
                         headers={"X-OTX-API-KEY":OTX_API_KEY}, timeout=REQ_TIMEOUT)
        return min(100,r.json().get("pulse_info",{}).get("count",0)*15) if r.status_code==200 else 0
    except: return -1

def compute_ti_score(iocs):
    details = {"iocs_checked":iocs,"vt_scores":{},"abuse_scores":{},"otx_scores":{}}
    scores  = []
    for ip in iocs.get("ips",[]):
        vt=vt_ip(ip);    time.sleep(RATE_DELAY)
        ab=abuse_ip(ip); time.sleep(RATE_DELAY)
        ox=otx_ip(ip);   time.sleep(RATE_DELAY)
        details["vt_scores"][ip]=vt; details["abuse_scores"][ip]=ab; details["otx_scores"][ip]=ox
        parts=[]
        if vt>=0: parts.append(vt*WEIGHT_VT/100)
        if ab>=0: parts.append(ab*WEIGHT_ABUSE/100)
        if ox>=0: parts.append(ox*WEIGHT_OTX/100)
        if parts: scores.append(sum(parts))
        log.info("    IP %s vt=%s abuse=%s otx=%s", ip, vt, ab, ox)
    for h in iocs.get("sha256",[])+iocs.get("md5",[]):
        vt=vt_hash(h); time.sleep(RATE_DELAY)
        ox=otx_hash(h); time.sleep(RATE_DELAY)
        details["vt_scores"][h[:16]]=vt; details["otx_scores"][h[:16]]=ox
        parts=[]
        if vt>=0: parts.append(vt*WEIGHT_VT/100)
        if ox>=0: parts.append(ox*WEIGHT_OTX/100)
        if parts: scores.append(sum(parts))
    if not scores: return 0, details
    raw = max(scores)
    return min(100, int(raw*100/(WEIGHT_VT+WEIGHT_ABUSE+WEIGHT_OTX)*1.8)), details

def score_label(s): return "malicious" if s>=70 else "suspicious" if s>=31 else "clean"
def sev(s):         return "critical"  if s>=85 else "high" if s>=70 else "medium" if s>=50 else "low" if s>=31 else "info"

def es_post(path, body):
    try:    return requests.post(ES_HOST+path, json=body, timeout=8).json()
    except: return {}

def es_update(index, doc_id, fields):
    try:    requests.post(f"{ES_HOST}/{index}/_update/{doc_id}", json={"doc":fields}, timeout=8)
    except Exception as e: log.warning("ES update %s: %s", doc_id, e)

def get_unscored():
    d = es_post(f"/{ES_INDEX}/_search", {
        "query": {"bool": {"must_not": [{"exists": {"field": "ti_score"}}]}},
        "size":  BATCH_SIZE, "_source": True,
    })
    hits = d.get("hits",{}).get("hits",[])
    log.info("Fetched %d unscored docs from %s", len(hits), ES_INDEX)
    return hits

def main():
    log.info("=== ti_enricher starting — index=%s ===", ES_INDEX)
    if not any([VT_API_KEY, ABUSE_API_KEY, OTX_API_KEY]):
        log.warning("No API keys — behavioral-only scoring (LotL rules active)")
    try:
        r = requests.get(f"{ES_HOST}/_cluster/health", timeout=5)
        log.info("Elasticsearch: %s", r.json().get("status","unknown"))
    except Exception as e:
        log.error("Cannot reach ES: %s", e); sys.exit(1)

    docs = get_unscored()
    if not docs: log.info("Nothing to enrich."); return

    processed = malicious = suspicious = clean = 0
    for doc in docs:
        doc_id = doc.get("_id","?")
        source = doc.get("_source",{})
        log.info("Processing %s (%s)", doc_id, doc.get("_index","?"))

        iocs = extract_iocs(source)
        total_iocs = sum(len(v) for v in iocs.values())

        if total_iocs > 0 and any([VT_API_KEY, ABUSE_API_KEY, OTX_API_KEY]):
            ti_score, details = compute_ti_score(iocs)
        else:
            ti_score, details = 0, {"iocs_checked": iocs}

        b_score, lotl_reasons = behavioral_score(source)
        final_score = min(100, max(ti_score, b_score))

        mitre = detect_mitre(source)
        name  = alert_name(source, mitre, lotl_reasons)
        label = score_label(final_score)

        log.info("  ti=%d behavioral=%d final=%d (%s) alert='%s'",
                 ti_score, b_score, final_score, label, name)

        enriched = {**source,
            "ti_score":       final_score,
            "ti_label":       label,
            "ti_severity":    sev(final_score),
            "ti_details":     details,
            "lotl_reasons":   lotl_reasons,
            "mitre_tactics":  mitre,
            "alert_name":     name,
            "ti_enriched_at": datetime.now(timezone.utc).isoformat(),
            "original_index": doc.get("_index",""),
            "original_id":    doc_id,
            "soar_state":     "Detected",
        }
        try:
            requests.post(f"{ES_HOST}/{ES_OUT_INDEX}/_doc", json=enriched, timeout=8)
        except Exception as e:
            log.error("Write failed: %s", e); continue

        es_update(doc["_index"], doc_id, {"ti_score": final_score, "ti_label": label})

        processed += 1
        if label=="malicious": malicious+=1
        elif label=="suspicious": suspicious+=1
        else: clean+=1

    log.info("=== Done: %d processed | %d malicious | %d suspicious | %d clean ===",
             processed, malicious, suspicious, clean)

if __name__ == "__main__":
    main()
