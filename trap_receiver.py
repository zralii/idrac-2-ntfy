#!/usr/bin/env python3
"""
idrac-2-ntfy — SNMP trap receiver that forwards Dell iDRAC alerts to ntfy.

Listens for SNMP v1/v2c traps from iDRAC and posts them to a configurable
ntfy topic using Bearer-token authentication.
"""

import logging
import os
import signal
import sys
import threading
from datetime import datetime, timezone

import requests
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config, engine
from pysnmp.entity.rfc3413 import ntfrcv

from idrac_oids import (
    DELL_ENTERPRISE_OID,
    get_severity,
    get_trap_category,
    resolve_var_name,
)

# ---------------------------------------------------------------------------
# Configuration (all from environment)
# ---------------------------------------------------------------------------
SNMP_LISTEN_ADDRESS = os.getenv("SNMP_LISTEN_ADDRESS", "0.0.0.0")
SNMP_LISTEN_PORT = int(os.getenv("SNMP_LISTEN_PORT", "162"))
SNMP_COMMUNITY = os.getenv("SNMP_COMMUNITY", "public")

NTFY_URL = os.getenv("NTFY_URL", "")            # e.g. https://ntfy.example.com/idrac
NTFY_TOKEN = os.getenv("NTFY_TOKEN", "")         # Bearer token
NTFY_PRIORITY = os.getenv("NTFY_PRIORITY", "")   # optional default priority override
NTFY_TAGS = os.getenv("NTFY_TAGS", "")           # optional extra tags (comma-sep)

IDRAC_LABEL = os.getenv("IDRAC_LABEL", "iDRAC")  # friendly name for the server

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("idrac2ntfy")

# ---------------------------------------------------------------------------
# ntfy priority mapping
# ---------------------------------------------------------------------------
SEVERITY_TO_NTFY_PRIORITY = {
    "ok": "low",
    "other": "default",
    "unknown": "default",
    "nonCritical": "high",
    "critical": "urgent",
    "nonRecoverable": "urgent",
}


def send_to_ntfy(title: str, message: str, priority: str, tags: list[str]) -> None:
    """Post an alert to the ntfy server."""
    if not NTFY_URL:
        log.error("NTFY_URL is not set — cannot forward alert")
        return

    headers = {
        "Title": title,
        "Priority": priority,
        "Tags": ",".join(tags),
        "Authorization": f"Bearer {NTFY_TOKEN}",
    }

    try:
        resp = requests.post(NTFY_URL, data=message.encode("utf-8"), headers=headers, timeout=15)
        resp.raise_for_status()
        log.info("Alert forwarded to ntfy  (status %s)", resp.status_code)
    except requests.RequestException as exc:
        log.error("Failed to forward alert to ntfy: %s", exc)


def parse_trap_vars(var_binds: list) -> dict:
    """Extract key-value pairs from SNMP trap variable bindings."""
    parsed: dict[str, str] = {}
    raw_oids: dict[str, str] = {}

    for oid, val in var_binds:
        oid_str = oid.prettyPrint()
        val_str = val.prettyPrint()

        # Try to resolve known Dell OID names
        friendly = resolve_var_name(oid_str)
        parsed[friendly] = val_str
        raw_oids[oid_str] = val_str

    return parsed, raw_oids


def determine_severity(parsed: dict) -> tuple[str, str]:
    """Determine severity from parsed trap data."""
    status_str = parsed.get("alertCurrentStatus", "")
    try:
        status_code = int(status_str)
    except (ValueError, TypeError):
        status_code = 0
    return get_severity(status_code)


def build_ntfy_message(parsed: dict, trap_oid: str, source_addr: str) -> tuple[str, str, str, list[str]]:
    """
    Build the ntfy notification from parsed trap data.
    Returns (title, message, priority, tags).
    """
    category = get_trap_category(trap_oid)
    severity_name, emoji = determine_severity(parsed)

    # Title - just the alert message from iDRAC
    alert_msg = parsed.get("alertMessage", "No message provided")
    title = f"{IDRAC_LABEL}: {alert_msg}"

    # Body
    msg_id = parsed.get("alertMessageID", "N/A")
    fqdn = parsed.get("systemFQDN", source_addr)
    svc_tag = parsed.get("systemServiceTag", parsed.get("chassisServiceTag", "N/A"))
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        f"{emoji} {alert_msg}",
        "",
        f"Host: {fqdn}",
        f"Service Tag: {svc_tag}",
        f"Severity: {severity_name}",
        f"Message ID: {msg_id}",
        f"Category: {category}",
        f"Source: {source_addr}",
        f"Time: {timestamp}",
    ]
    message = "\n".join(lines)

    # Priority
    priority = NTFY_PRIORITY or SEVERITY_TO_NTFY_PRIORITY.get(severity_name, "default")

    # Tags
    tags = ["server", category.lower().replace(" ", "_")]
    if severity_name in ("critical", "nonRecoverable"):
        tags.append("rotating_light")
    elif severity_name == "nonCritical":
        tags.append("warning")
    elif severity_name == "ok":
        tags.append("white_check_mark")
    if NTFY_TAGS:
        tags.extend(t.strip() for t in NTFY_TAGS.split(",") if t.strip())

    return title, message, priority, tags


# ---------------------------------------------------------------------------
# SNMP trap callback
# ---------------------------------------------------------------------------
def trap_callback(snmp_engine, state_reference, context_engine_id, context_name,
                  var_binds, cb_ctx):
    """Called by pysnmp whenever a trap/notification is received."""
    transport_domain, transport_address = snmp_engine.msgAndPduDsp.getTransportInfo(state_reference)
    source_addr = f"{transport_address[0]}:{transport_address[1]}" if transport_address else "unknown"

    log.info("Trap received from %s", source_addr)

    # Identify the trap OID (SNMPv2-MIB::snmpTrapOID.0 = 1.3.6.1.6.3.1.1.4.1.0)
    trap_oid = ""
    for oid, val in var_binds:
        oid_str = oid.prettyPrint()
        if oid_str == "1.3.6.1.6.3.1.1.4.1.0":
            trap_oid = val.prettyPrint()
            break

    parsed, raw_oids = parse_trap_vars(var_binds)

    log.debug("Trap OID: %s", trap_oid)
    log.debug("Parsed vars: %s", parsed)

    # Only process Dell iDRAC traps; log and skip others
    if not trap_oid.startswith(DELL_ENTERPRISE_OID):
        log.info("Non-Dell trap (%s) — skipping", trap_oid)
        return

    title, message, priority, tags = build_ntfy_message(
        parsed, trap_oid, transport_address[0] if transport_address else "unknown"
    )

    log.info("Forwarding: %s [%s]", title, priority)

    # Send in a thread to avoid blocking the SNMP engine
    threading.Thread(
        target=send_to_ntfy,
        args=(title, message, priority, tags),
        daemon=True,
    ).start()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    if not NTFY_URL:
        log.error("NTFY_URL environment variable is required")
        sys.exit(1)
    if not NTFY_TOKEN:
        log.warning("NTFY_TOKEN is not set — requests will be unauthenticated")

    log.info("Starting idrac-2-ntfy SNMP trap receiver")
    log.info("  Listen: %s:%s  Community: %s", SNMP_LISTEN_ADDRESS, SNMP_LISTEN_PORT, SNMP_COMMUNITY)
    log.info("  ntfy target: %s", NTFY_URL)

    # Create SNMP engine
    snmp_engine = engine.SnmpEngine()

    # Transport — listen on UDP
    config.addTransport(
        snmp_engine,
        udp.domainName,
        udp.UdpAsyncioTransport().openServerMode(
            (SNMP_LISTEN_ADDRESS, SNMP_LISTEN_PORT)
        ),
    )

    # SNMPv1/v2c community
    config.addV1System(snmp_engine, "idrac-area", SNMP_COMMUNITY)

    # Register the callback for incoming notifications
    ntfrcv.NotificationReceiver(snmp_engine, trap_callback)

    log.info("Listening for SNMP traps …")

    # Graceful shutdown
    def shutdown(signum, frame):
        log.info("Shutting down (signal %s) …", signum)
        snmp_engine.transportDispatcher.jobFinished(1)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    try:
        snmp_engine.transportDispatcher.jobStarted(1)
        snmp_engine.transportDispatcher.runDispatcher()
    except Exception:
        snmp_engine.transportDispatcher.closeDispatcher()
        raise

    log.info("Stopped.")


if __name__ == "__main__":
    main()
