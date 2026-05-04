#!/usr/bin/env python3
"""
soar.py — Full Active-Response SOAR Engine (Upgraded)
======================================================
Upgrades from original:
  1. ACTIVE RESPONSE — kills processes, isolates hosts, blocks IPs (was collect-only)
  2. Tiered playbooks by severity:
       score >= 85 → PB-03 CRITICAL: full forensics + network isolate
       score >= 70 + bad IPs  → PB-01: block IPs + collect netstat/pslist
       score >= 70 + bad hash → PB-02: kill process + collect evidence
       score 31-69 → PB-04: collect only (suspicious, no blocking)
  3. State machine: Detected → In-Progress → Remediated written to ES
  4. C2 beacon detection: repeated connections to same external IP
  5. Poll interval: 5s (was 300s)
  6. Logs both to file and stdout
"""

import os, sys, json, time, logging, ipaddress, subprocess, re
import requests
from datetime import datetime, timezone, timedelta
from collections import defaultdict

ES              = os.getenv("ES_HOST",          "http://192.168.23.130:9200")
ENRICH_IDX      = os.getenv("ES_ENRICHED_IDX",  "ti-enriched")
POLL_INTERVAL   = int(os.getenv("POLL_INTERVAL", "5"))
VR_CONFIG       = "/etc/velociraptor/server.config.yaml"
SOAR_LOG        = "/var/log/soar.log"

THRESH_CRITICAL   = 85
THRESH_MALICIOUS  = 70
THRESH_SUSPICIOUS = 31

C2_THRESHOLD = 5      # connections to same IP within window = C2 beacon
C2_WINDOW    = 10     # minutes

PRIVATE_NETS = [ipaddress.ip_network(n) for n in
                ["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8"]]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    handlers=[
        logging.FileHandler(SOAR_LOG),
        logging.StreamHandler(sys.stdout),
    ])
log = logging.getLogger("soar")

ALERTED_IDS = set()

def is_private(ip):
    try:    return any(ipaddress.ip_address(ip) in n for n in PRIVATE_NETS)
    except: return True

def now_iso(): return datetime.now(timezone.utc).isoformat()

# ── Elasticsearch ────────────────────────────────────────────
def es_search(index, body):
    try:    return requests.post(f"{ES}/{index}/_search", json=body, timeout=10).json().get("hits",{}).get("hits",[])
    except Exception as e: log.error("ES search: %s", e); return []

def es_update(index, doc_id, fields):
    try:    requests.post(f"{ES}/{index}/_update/{doc_id}", json={"doc":fields}, timeout=10)
    except Exception as e: log.warning("ES update %s: %s", doc_id, e)

def es_index(index, doc):
    try:    requests.post(f"{ES}/{index}/_doc", json=doc, timeout=10)
    except Exception as e: log.warning("ES index: %s", e)

def fetch_unactioned(threshold):
    return es_search(ENRICH_IDX, {
        "query": {"bool": {
            "must":     [{"range": {"ti_score": {"gte": threshold}}}],
            "must_not": [{"exists": {"field": "soar_actioned"}}]
        }},
        "size": 20, "_source": True,
    })

# ── Velociraptor VQL ─────────────────────────────────────────
def vr_run(vql, timeout=30):
    try:
        r = subprocess.run(
            ["velociraptor","--config",VR_CONFIG,"query",vql,"--format","json"],
            capture_output=True, text=True, timeout=timeout)
        return (True, r.stdout.strip()) if r.returncode==0 else (False, r.stderr[:300])
    except subprocess.TimeoutExpired: return False, "timeout"
    except FileNotFoundError:         return False, "velociraptor not found"
    except Exception as e:            return False, str(e)

def vr_get_client(hostname):
    ok, out = vr_run(f'SELECT client_id FROM clients() WHERE os_info.hostname =~ "{hostname}"')
    if not ok: return None
    try:
        rows = json.loads(out or "[]")
        return rows[0].get("client_id") if rows else None
    except: return None

def vr_collect(cid, artifacts):
    arts = json.dumps(artifacts)
    ok, out = vr_run(
        f'SELECT collect_client(client_id="{cid}",artifacts={arts},spec=dict()) FROM scope()',
        timeout=30)
    if not ok: return False, out
    try:
        rows = json.loads(out or "[{}]")
        return True, (rows[0] if rows else {}).get("flow_id","unknown")
    except: return True, "unknown"

def vr_bash(cid, cmd):
    safe = cmd.replace('"','\\"')
    ok, out = vr_run(
        f'SELECT collect_client(client_id="{cid}",'
        f'artifacts=["Linux.System.BashShell"],'
        f'spec=dict(`Linux.System.BashShell`=dict(Command="{safe}"))) FROM scope()',
        timeout=30)
    if not ok: return False, out
    try:
        rows = json.loads(out or "[{}]")
        return True, (rows[0] if rows else {}).get("flow_id","done")
    except: return True, "done"

def vr_kill_pid(cid, pid):
    return vr_bash(cid, f"kill -9 {pid} 2>/dev/null && echo killed_{pid} || echo not_found")

def vr_block_ip(cid, ip):
    cmd = (f"iptables -I OUTPUT -d {ip} -j DROP 2>/dev/null; "
           f"iptables -I INPUT -s {ip} -j DROP 2>/dev/null; echo blocked_{ip}")
    return vr_bash(cid, cmd)

def vr_isolate(cid, soc_ip="192.168.23.130"):
    cmd = (
        "iptables -P INPUT DROP; iptables -P OUTPUT DROP; iptables -P FORWARD DROP; "
        f"iptables -A INPUT -s {soc_ip} -j ACCEPT; "
        f"iptables -A OUTPUT -d {soc_ip} -j ACCEPT; "
        "iptables -A INPUT -i lo -j ACCEPT; "
        "iptables -A OUTPUT -o lo -j ACCEPT; echo isolated"
    )
    return vr_bash(cid, cmd)

# ── Playbook result ──────────────────────────────────────────
class PBResult:
    def __init__(self, name, host, score):
        self.name=name; self.host=host; self.score=score
        self.steps=[]; self.flow_ids={}; self.actions=[]
    def step(self, label, ok, detail=""):
        self.steps.append({"step":label,"status":"success" if ok else "failed",
                           "detail":str(detail)[:200],"ts":datetime.now().strftime("%H:%M:%S")})
        log.info("  %s [%s] %s %s","OK" if ok else "ERR",self.name,label,str(detail)[:60])
    def summary(self):
        ok=[s["step"] for s in self.steps if s["status"]=="success"]
        return f"{self.name} ok=[{','.join(ok)}] actions=[{','.join(self.actions)}]"

# ── PB-01: Malicious IP ──────────────────────────────────────
def pb01_malicious_ip(cid, host, score, bad_ips):
    pb = PBResult("PB-01-MALICIOUS-IP", host, score)
    log.warning("[PB-01] Malicious IP on %s score=%d ips=%s", host, score, bad_ips)

    ok1,f1 = vr_collect(cid, ["Linux.Network.NetstatEnriched","Linux.Sys.Pslist"])
    pb.step("collect_netstat_pslist", ok1, f"flow={f1}")
    if ok1: pb.flow_ids["netstat_pslist"]=f1

    for ip in bad_ips[:5]:
        ok2,d2 = vr_block_ip(cid, ip)
        pb.step(f"block_ip_{ip}", ok2, d2)
        if ok2: pb.actions.append(f"Blocked {ip}")

    ok3,f3 = vr_collect(cid, ["Linux.Sys.BashHistory"])
    pb.step("collect_bash_history", ok3, f"flow={f3}")
    if ok3: pb.flow_ids["bash_history"]=f3
    return pb

# ── PB-02: Malicious Hash ────────────────────────────────────
def pb02_malicious_hash(cid, host, score, bad_hashes, source):
    pb = PBResult("PB-02-MALICIOUS-HASH", host, score)
    log.warning("[PB-02] Malicious hash on %s score=%d", host, score)

    ok1,f1 = vr_collect(cid, ["Linux.Sys.Pslist"])
    pb.step("collect_pslist", ok1, f"flow={f1}")
    if ok1: pb.flow_ids["pslist"]=f1

    path = (source.get("file") or {}).get("path","")
    if path and path not in ("","-"):
        ok2,d2 = vr_bash(cid, f"pkill -f '{path}' 2>/dev/null; echo done")
        pb.step("kill_process_by_path", ok2, path[:60])
        if ok2: pb.actions.append(f"Killed: {path[:40]}")
    else:
        pb.step("kill_process_by_path", False, "no path in event")

    ok3,f3 = vr_collect(cid, ["Linux.Search.FileFinder","Linux.Sys.BashHistory"])
    pb.step("collect_file_evidence", ok3, f"flow={f3}")
    if ok3: pb.flow_ids["file_evidence"]=f3
    return pb

# ── PB-03: Critical ──────────────────────────────────────────
def pb03_critical(cid, host, score):
    pb = PBResult("PB-03-CRITICAL", host, score)
    log.warning("[PB-03] CRITICAL on %s score=%d — full forensic + isolate", host, score)

    ok1,f1 = vr_collect(cid, [
        "Generic.Client.Info","Linux.Sys.Pslist",
        "Linux.Network.NetstatEnriched","Linux.Sys.BashHistory","Linux.Sys.Users"])
    pb.step("full_forensic_collection", ok1, f"flow={f1}")
    if ok1: pb.flow_ids["forensics"]=f1

    ok2,d2 = vr_bash(cid,
        "crontab -l 2>/dev/null; "
        "systemctl list-units --type=service --state=running 2>/dev/null | head -20")
    pb.step("check_persistence", ok2, "cron+services")

    ok3,d3 = vr_bash(cid, "lsmod | head -20")
    pb.step("check_kernel_modules", ok3, "lsmod collected")

    ok4,d4 = vr_isolate(cid)
    pb.step("network_isolation", ok4, "host isolated — only SOC traffic" if ok4 else d4)
    if ok4: pb.actions.append("Network Isolated")
    return pb

# ── PB-04: Suspicious ────────────────────────────────────────
def pb04_suspicious(cid, host, score, source):
    pb = PBResult("PB-04-SUSPICIOUS", host, score)
    log.info("[PB-04] Suspicious on %s score=%d — evidence only", host, score)

    ok1,f1 = vr_collect(cid, ["Linux.Sys.Pslist"])
    pb.step("collect_processes", ok1, f"flow={f1}")
    if ok1: pb.flow_ids["pslist"]=f1

    ok2,f2 = vr_collect(cid, ["Linux.Sys.BashHistory"])
    pb.step("collect_bash_history", ok2, f"flow={f2}")
    if ok2: pb.flow_ids["bash_history"]=f2

    ok3,f3 = vr_collect(cid, ["Linux.Network.NetstatEnriched"])
    pb.step("collect_network_state", ok3, f"flow={f3}")

    ok4,d4 = vr_bash(cid, "last -n 10 2>/dev/null; grep sudo /var/log/auth.log 2>/dev/null | tail -5")
    pb.step("check_user_activity", ok4, "auth log")
    return pb

# ── Playbook selector ────────────────────────────────────────
def select_playbook(doc_id, source):
    score    = source.get("ti_score", 0)
    details  = source.get("ti_details") or {}
    iocs     = details.get("iocs_checked") or {}
    vt_sc    = details.get("vt_scores",    {})
    abuse_sc = details.get("abuse_scores", {})
    otx_sc   = details.get("otx_scores",   {})
    hostname = (
        (source.get("host") or {}).get("hostname") or
        (source.get("host") or {}).get("name") or
        (source.get("agent") or {}).get("name") or "unknown"
    )

    if hostname == "unknown":
        log.warning("  Cannot determine hostname for %s — logging only", doc_id)
        return None, hostname

    cid = vr_get_client(hostname)
    if not cid:
        log.warning("  No VR client for '%s' — logging only", hostname)
        return None, hostname

    log.info("  Resolved host=%s cid=%s", hostname, cid)

    bad_ips = [ip for ip in iocs.get("ips",[])
               if not is_private(ip) and
               (vt_sc.get(ip,0)>0 or abuse_sc.get(ip,0)>0 or otx_sc.get(ip,0)>0)]

    bad_hashes = [h for h in iocs.get("sha256",[])+iocs.get("md5",[])
                  if vt_sc.get(h[:16],-1)>0 or otx_sc.get(h[:16],-1)>0]

    if score >= THRESH_CRITICAL:
        return pb03_critical(cid, hostname, score), hostname
    if score >= THRESH_MALICIOUS and bad_ips:
        return pb01_malicious_ip(cid, hostname, score, bad_ips), hostname
    if score >= THRESH_MALICIOUS and bad_hashes:
        return pb02_malicious_hash(cid, hostname, score, bad_hashes, source), hostname
    if score >= THRESH_SUSPICIOUS:
        return pb04_suspicious(cid, hostname, score, source), hostname
    return None, hostname

# ── C2 beacon detector ───────────────────────────────────────
_c2_checked = set()

def check_c2_beacons():
    try:
        d = requests.post(f"{ES}/soc-logs-*/_search", json={
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": f"now-{C2_WINDOW}m"}}},
            "aggs": {"hosts": {"terms": {"field": "host.name","size":20}}}
        }, timeout=10).json()
        hosts = [b["key"] for b in d.get("aggregations",{}).get("hosts",{}).get("buckets",[])]
    except: return

    for host in hosts:
        try:
            conns = es_search("soc-logs-*", {
                "query": {"bool": {"must": [
                    {"match": {"host.name": host}},
                    {"range": {"@timestamp": {"gte": f"now-{C2_WINDOW}m"}}},
                    {"exists": {"field": "destination.ip"}}
                ]}},
                "size": 100, "_source": ["destination.ip","@timestamp"]
            })
        except: continue

        ip_counts = defaultdict(int)
        for h in conns:
            dst = (h.get("_source",{}).get("destination") or {}).get("ip","")
            if dst and not is_private(dst):
                ip_counts[dst] += 1

        beacon_ips = [ip for ip,cnt in ip_counts.items() if cnt >= C2_THRESHOLD]
        if not beacon_ips: continue

        key = f"c2:{host}:{','.join(sorted(beacon_ips))}"
        if key in _c2_checked: continue
        _c2_checked.add(key)

        log.warning("C2 BEACON host=%s ips=%s", host, beacon_ips)
        cid = vr_get_client(host)
        if not cid: continue

        pb = PBResult("PB-05-C2-BEACON", host, 0)
        ok1,f1 = vr_collect(cid, ["Linux.Network.NetstatEnriched"])
        pb.step("collect_network_state", ok1, f"flow={f1}")
        for ip in beacon_ips[:3]:
            ok2,d2 = vr_block_ip(cid, ip)
            pb.step(f"block_beacon_ip_{ip}", ok2, d2)
        ok3,f3 = vr_collect(cid, ["Linux.Sys.Pslist","Linux.Sys.BashHistory"])
        pb.step("collect_forensics", ok3, f"flow={f3}")

        es_index(ENRICH_IDX, {
            "alert_name":"C2 Beacon Detected","playbook":"PB-05-C2-BEACON",
            "host":{"hostname":host},"beacon_ips":beacon_ips,
            "ti_score":0,"ti_label":"suspicious","ti_severity":"medium",
            "soar_state":"Remediated","soar_actioned":True,
            "soar_steps":pb.steps,"soar_time":now_iso(),
        })

# ── Alert handler ────────────────────────────────────────────
def handle_alert(doc):
    doc_id = doc["_id"]
    source = doc.get("_source",{})
    score  = source.get("ti_score",0)
    name   = source.get("alert_name","Threat Intel Match")
    host   = ((source.get("host") or {}).get("hostname") or
               (source.get("agent") or {}).get("name") or "unknown")

    if doc_id in ALERTED_IDS: return
    ALERTED_IDS.add(doc_id)

    log.info("━"*55)
    log.info("ALERT doc=%s score=%d host=%s name=%s", doc_id[:12], score, host, name)

    # Set state → In-Progress
    es_update(ENRICH_IDX, doc_id, {"soar_state":"In-Progress","soar_started_at":now_iso()})

    result, hostname = select_playbook(doc_id, source)

    if result:
        playbook = result.name
        summary  = result.summary()
        steps    = result.steps
        flow_ids = result.flow_ids
        action   = ",".join(result.actions) if result.actions else "evidence_collected"
        log.info("  Playbook result: %s", summary)
    else:
        playbook = "PB-00-LOGGED-ONLY"
        summary  = f"no VR client for {hostname}"
        steps    = []; flow_ids = {}; action = "logged_only"

    es_update(ENRICH_IDX, doc_id, {
        "soar_state":             "Remediated",
        "soar_actioned":          True,
        "soar_playbook":          playbook,
        "soar_action":            action,
        "soar_action_details":    summary,
        "soar_steps":             steps,
        "velociraptor_flow_id":   list(flow_ids.values())[0] if flow_ids else None,
        "velociraptor_flow_ids":  flow_ids,
        "soar_time":              now_iso(),
    })
    log.info("  Marked Remediated in ES — playbook=%s", playbook)

# ── Main ─────────────────────────────────────────────────────
def main():
    log.info("="*55)
    log.info("SOC SOAR Engine — Full Active Response")
    log.info("  PB-01 Malicious IP:   score>=%d + bad IPs  → block + collect", THRESH_MALICIOUS)
    log.info("  PB-02 Malicious Hash: score>=%d + bad hash → kill + collect",  THRESH_MALICIOUS)
    log.info("  PB-03 Critical:       score>=%d            → full forensic + isolate", THRESH_CRITICAL)
    log.info("  PB-04 Suspicious:     score>=%d            → collect only",    THRESH_SUSPICIOUS)
    log.info("  PB-05 C2 Beacon:      >%d conns/%dm        → block + collect", C2_THRESHOLD, C2_WINDOW)
    log.info("  Poll: %ds", POLL_INTERVAL)
    log.info("="*55)

    try:
        r = requests.get(f"{ES}/_cluster/health", timeout=5)
        log.info("Elasticsearch: %s", r.json().get("status","unknown"))
    except Exception as e:
        log.error("Cannot reach ES: %s", e); sys.exit(1)

    ok, out = vr_run("SELECT version() FROM scope()", timeout=10)
    log.info("Velociraptor: %s", "connected" if ok else f"unavailable ({out[:50]})")

    poll = 0
    while True:
        poll += 1
        log.info("── Poll #%d ──", poll)

        docs = fetch_unactioned(THRESH_SUSPICIOUS)
        if not docs:
            log.info("  No unactioned alerts")
        else:
            log.info("  %d unactioned alerts", len(docs))
            for doc in docs:
                try:    handle_alert(doc)
                except Exception as e: log.error("  handle_alert error: %s", e)

        if poll % 3 == 0:
            try:    check_c2_beacons()
            except Exception as e: log.error("  C2 check error: %s", e)

        log.info("  Sleeping %ds…", POLL_INTERVAL)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
