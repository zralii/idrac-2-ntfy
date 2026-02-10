"""
Dell iDRAC SNMP OID mappings for human-readable alert messages.

Reference: Dell iDRAC MIB (iDRAC-SMIv2.mib / IDRAC-MIB-SMIv2.mib)
Enterprise OID: 1.3.6.1.4.1.674.10892.5
"""

# Dell enterprise OID prefix
DELL_ENTERPRISE_OID = "1.3.6.1.4.1.674"
IDRAC_OID_PREFIX = "1.3.6.1.4.1.674.10892.5"

# Common iDRAC trap variable OIDs
TRAP_VARS = {
    # Alert message string
    "1.3.6.1.4.1.674.10892.5.3.1.1": "alertMessage",
    # Alert current status
    "1.3.6.1.4.1.674.10892.5.3.1.2": "alertCurrentStatus",
    # Alert previous status
    "1.3.6.1.4.1.674.10892.5.3.1.3": "alertPreviousStatus",
    # Alert message ID
    "1.3.6.1.4.1.674.10892.5.3.1.4": "alertMessageID",
    # System FQDN
    "1.3.6.1.4.1.674.10892.5.1.1.1": "systemFQDN",
    # System service tag
    "1.3.6.1.4.1.674.10892.5.1.1.11": "systemServiceTag",
    # Chassis service tag
    "1.3.6.1.4.1.674.10892.5.4.300.1": "chassisServiceTag",
    # Alternative OIDs (used in some iDRAC versions/test traps)
    "1.3.6.1.4.1.674.10892.5.4.300.1.6": "alertMessage",
    "1.3.6.1.4.1.674.10892.5.4.300.1.8": "alertCurrentStatus",
}

# Severity mapping from iDRAC status codes
SEVERITY_MAP = {
    1: ("other", "ℹ️"),
    2: ("unknown", "❓"),
    3: ("ok", "✅"),
    4: ("nonCritical", "⚠️"),
    5: ("critical", "🔴"),
    6: ("nonRecoverable", "🚨"),
}

# iDRAC trap OID to category mapping
# These are the specific trap OIDs sent by iDRAC
TRAP_CATEGORIES = {
    # ---- Test trap ----
    "1.3.6.1.4.1.674.10892.5.0.10395": "Test Alert",
    "1.3.6.1.4.1.674.10892.5.3.2.29": "Test Alert",
    # ---- Temperature ----
    "1.3.6.1.4.1.674.10892.5.3.2.1": "Temperature Warning",
    "1.3.6.1.4.1.674.10892.5.3.2.2": "Temperature Critical",
    # ---- Voltage ----
    "1.3.6.1.4.1.674.10892.5.3.2.3": "Voltage Warning",
    "1.3.6.1.4.1.674.10892.5.3.2.4": "Voltage Critical",
    # ---- Fan / Cooling ----
    "1.3.6.1.4.1.674.10892.5.3.2.5": "Fan Warning",
    "1.3.6.1.4.1.674.10892.5.3.2.6": "Fan Critical",
    # ---- Power Supply ----
    "1.3.6.1.4.1.674.10892.5.3.2.7": "Power Supply Warning",
    "1.3.6.1.4.1.674.10892.5.3.2.8": "Power Supply Critical",
    # ---- Memory ----
    "1.3.6.1.4.1.674.10892.5.3.2.9": "Memory Warning",
    "1.3.6.1.4.1.674.10892.5.3.2.10": "Memory Critical",
    # ---- Storage / Physical Disk ----
    "1.3.6.1.4.1.674.10892.5.3.2.11": "Storage Warning",
    "1.3.6.1.4.1.674.10892.5.3.2.12": "Storage Critical",
    # ---- CPU / Processor ----
    "1.3.6.1.4.1.674.10892.5.3.2.13": "Processor Warning",
    "1.3.6.1.4.1.674.10892.5.3.2.14": "Processor Critical",
    # ---- Battery ----
    "1.3.6.1.4.1.674.10892.5.3.2.15": "Battery Warning",
    "1.3.6.1.4.1.674.10892.5.3.2.16": "Battery Critical",
    # ---- System Event Log ----
    "1.3.6.1.4.1.674.10892.5.3.2.17": "System Event",
    # ---- Hardware Log ----
    "1.3.6.1.4.1.674.10892.5.3.2.18": "Hardware Event",
    # ---- Redundancy ----
    "1.3.6.1.4.1.674.10892.5.3.2.19": "Redundancy Warning",
    "1.3.6.1.4.1.674.10892.5.3.2.20": "Redundancy Lost",
    # ---- Power state changes ----
    "1.3.6.1.4.1.674.10892.5.3.2.21": "Power State Change",
    # ---- License ----
    "1.3.6.1.4.1.674.10892.5.3.2.22": "License Event",
    # ---- Network / NIC ----
    "1.3.6.1.4.1.674.10892.5.3.2.23": "Network Warning",
    "1.3.6.1.4.1.674.10892.5.3.2.24": "Network Critical",
    # ---- Virtual Disk ----
    "1.3.6.1.4.1.674.10892.5.3.2.25": "Virtual Disk Warning",
    "1.3.6.1.4.1.674.10892.5.3.2.26": "Virtual Disk Critical",
    # ---- RAID Controller ----
    "1.3.6.1.4.1.674.10892.5.3.2.27": "RAID Controller Warning",
    "1.3.6.1.4.1.674.10892.5.3.2.28": "RAID Controller Critical",
    # ---- Generic/Unknown Dell trap ----
    "1.3.6.1.4.1.674.10892.5": "iDRAC Alert",
}


def get_trap_category(trap_oid: str) -> str:
    """Resolve a trap OID to its human-readable category."""
    return TRAP_CATEGORIES.get(trap_oid, f"iDRAC Alert ({trap_oid})")


def get_severity(status_code: int) -> tuple[str, str]:
    """Return (severity_name, emoji) for a given iDRAC status code."""
    return SEVERITY_MAP.get(status_code, ("unknown", "❓"))


def resolve_var_name(oid: str) -> str:
    """Resolve a trap variable OID to a human-readable field name."""
    return TRAP_VARS.get(oid, oid)
