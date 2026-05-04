"""
soar_logger.py — Full terminal-style SOAR logger
==================================================
Every SOAR step is written with timestamp, severity, and context.
Log entries are also stored in Elasticsearch for the dashboard to query.
"""

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

SOAR_LOG  = "/var/log/soar.log"
ES_HOST   = "http://192.168.23.130:9200"
LOG_INDEX = "soar-log"

# ANSI colour codes for stdout
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
BLUE   = "\033[34m"
CYAN   = "\033[36m"
DIM    = "\033[2m"

# ── Internal log queue (last 500 lines for SSE) ──────────────
_log_buffer: list[dict] = []
MAX_BUFFER = 500


def _ts() -> str:
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]


def _level_fmt(level: str) -> tuple[str, str]:
    """Returns (colour, label) for a log level."""
    return {
        "INFO":    (BLUE,   "INFO "),
        "OK":      (GREEN,  "OK   "),
        "WARN":    (YELLOW, "WARN "),
        "ERROR":   (RED,    "ERROR"),
        "ACTION":  (CYAN,   "ACT  "),
        "ALERT":   (RED+BOLD,"ALERT"),
        "STEP":    (DIM,    "STEP "),
        "SOAR":    (CYAN+BOLD,"SOAR"),
    }.get(level, (DIM, level[:5].ljust(5)))


def _write_file(line: str):
    try:
        with open(SOAR_LOG, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def _write_es(entry: dict):
    try:
        requests.post(
            f"{ES_HOST}/{LOG_INDEX}/_doc",
            json=entry,
            timeout=3
        )
    except Exception:
        pass


def log_entry(
    level: str,
    message: str,
    *,
    doc_id: Optional[str]  = None,
    host: Optional[str]    = None,
    playbook: Optional[str]= None,
    step: Optional[str]    = None,
    detail: Optional[str]  = None,
    flow_id: Optional[str] = None,
):
    """
    Write one terminal-style log entry everywhere:
      - stdout (coloured)
      - /var/log/soar.log (plain text)
      - Elasticsearch soar-log index
      - in-memory buffer (for SSE)
    """
    ts       = _ts()
    col, lbl = _level_fmt(level)

    # Build terminal line
    ctx_parts = []
    if host:     ctx_parts.append(f"host={host}")
    if doc_id:   ctx_parts.append(f"doc={doc_id[:12]}")
    if playbook: ctx_parts.append(f"pb={playbook}")
    if step:     ctx_parts.append(f"step={step}")
    if flow_id:  ctx_parts.append(f"flow={flow_id}")
    ctx = "  " + "  ".join(ctx_parts) if ctx_parts else ""

    plain_line = f"[{ts}]  {lbl}  {message}{ctx}"
    if detail:
        plain_line += f"\n              → {detail}"

    colour_line = f"{DIM}[{ts}]{RESET}  {col}{lbl}{RESET}  {message}{DIM}{ctx}{RESET}"
    if detail:
        colour_line += f"\n{DIM}              → {detail}{RESET}"

    # Stdout (coloured)
    print(colour_line, flush=True)

    # File (plain)
    _write_file(plain_line)

    # Memory buffer
    entry = {
        "ts":       ts,
        "level":    level,
        "message":  message,
        "host":     host,
        "doc_id":   doc_id,
        "playbook": playbook,
        "step":     step,
        "detail":   detail,
        "flow_id":  flow_id,
        "plain":    plain_line,
    }
    _log_buffer.append(entry)
    if len(_log_buffer) > MAX_BUFFER:
        _log_buffer.pop(0)

    # Elasticsearch (fire and forget)
    _write_es({**entry, "@timestamp": datetime.now(timezone.utc).isoformat()})


# ── Convenience helpers ──────────────────────────────────────

def info(msg: str, **kw):
    log_entry("INFO", msg, **kw)

def ok(msg: str, **kw):
    log_entry("OK", msg, **kw)

def warn(msg: str, **kw):
    log_entry("WARN", msg, **kw)

def error(msg: str, **kw):
    log_entry("ERROR", msg, **kw)

def action(msg: str, **kw):
    log_entry("ACTION", msg, **kw)

def alert(msg: str, **kw):
    log_entry("ALERT", msg, **kw)

def step(name: str, success: bool, **kw):
    level = "OK" if success else "ERROR"
    log_entry(level, f"{'✓' if success else '✗'} {name}", step=name, **kw)

def soar_header(playbook: str, host: str, score: int, doc_id: str):
    log_entry("SOAR",
              f"{'━'*55}",
              doc_id=doc_id, host=host, playbook=playbook)
    log_entry("ALERT",
              f"Playbook triggered: {playbook}",
              doc_id=doc_id, host=host, playbook=playbook,
              detail=f"score={score}")


def get_buffer(last_n: int = 200) -> list[dict]:
    """Return last N log entries from in-memory buffer."""
    return _log_buffer[-last_n:]


def get_log_lines(last_n: int = 100) -> list[str]:
    """Return last N plain-text log lines."""
    return [e["plain"] for e in _log_buffer[-last_n:]]


def read_log_file(last_n: int = 200) -> list[str]:
    """Read last N lines from log file (slower, but survives restart)."""
    try:
        lines = Path(SOAR_LOG).read_text().splitlines()
        return [l for l in lines[-last_n:] if l.strip()]
    except Exception:
        return []
