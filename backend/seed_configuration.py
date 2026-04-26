# idps-backend/seed_configuration.py
"""
Run once to populate the DB with initial config data.
  python seed_configuration.py
"""
from database import SessionLocal, engine, Base
from models.configuration import (
    SignatureRule, RansomwareRule, AnomalyConfig,
    NetworkInterface, AlertSettings, SystemSettings,
)

Base.metadata.create_all(bind=engine)  # creates tables if not yet done

db = SessionLocal()

# ── Signature Rules ────────────────────────────────────
SIG_RULES = [
    {"id":"SIG-001","name":"SQL Injection — UNION SELECT","category":"Web Attack",   "severity":"Critical","protocol":"HTTP","action":"Block","pattern":"UNION SELECT.*FROM","enabled":True},
    {"id":"SIG-002","name":"XSS Reflected Payload",       "category":"Web Attack",   "severity":"High",    "protocol":"HTTP","action":"Alert","pattern":"<script>.*alert","enabled":True},
    {"id":"SIG-003","name":"SYN Flood Detection",          "category":"DDoS",         "severity":"Critical","protocol":"TCP", "action":"Drop", "pattern":"SYN flags > 1000/s","enabled":True},
    {"id":"SIG-004","name":"SSH Brute Force",               "category":"Brute Force",  "severity":"High",    "protocol":"TCP", "action":"Block","pattern":"Failed password.*ssh","enabled":True},
    {"id":"SIG-005","name":"FTP Brute Force",               "category":"Brute Force",  "severity":"Medium",  "protocol":"FTP", "action":"Alert","pattern":"Login failed.*ftp","enabled":True},
    {"id":"SIG-006","name":"Nmap SYN Scan",                "category":"Recon",        "severity":"Medium",  "protocol":"TCP", "action":"Alert","pattern":"TCP SYN scan pattern","enabled":True},
    {"id":"SIG-007","name":"Emotet Dropper URL",           "category":"Malware",      "severity":"Critical","protocol":"HTTP","action":"Block","pattern":"emotet.*dropper.*url","enabled":True},
    {"id":"SIG-008","name":"HTTP Slowloris",               "category":"DDoS",         "severity":"High",    "protocol":"HTTP","action":"Drop", "pattern":"partial HTTP headers","enabled":True},
    {"id":"SIG-009","name":"Blind SQL Injection",          "category":"Web Attack",   "severity":"High",    "protocol":"HTTP","action":"Block","pattern":"sleep\\(|waitfor delay","enabled":True},
    {"id":"SIG-010","name":"RDP Brute Force",              "category":"Brute Force",  "severity":"Medium",  "protocol":"RDP", "action":"Alert","pattern":"Failed RDP login","enabled":False},
]

for r in SIG_RULES:
    if not db.query(SignatureRule).filter(SignatureRule.id == r["id"]).first():
        db.add(SignatureRule(**r))

# ── Ransomware Rules ───────────────────────────────────
RAN_RULES = [
    {"id":"RAN-001","name":"LockBit C2 Beacon",           "risk_level":"Critical","pattern":"lockbit.*c2.*beacon",        "enabled":True,  "last_triggered":"2026-02-24 09:00"},
    {"id":"RAN-002","name":"Shadow Copy Deletion",        "risk_level":"Critical","pattern":"vssadmin.*delete shadows",   "enabled":True,  "last_triggered":"2026-02-24 08:50"},
    {"id":"RAN-003","name":"Ryuk Registry Modification",  "risk_level":"Critical","pattern":"HKLM.*RUN.*ryuk",            "enabled":True,  "last_triggered":"2026-02-24 08:52"},
    {"id":"RAN-004","name":"AES Pattern in Traffic",      "risk_level":"High",    "pattern":"encrypted payload.*AES256",  "enabled":True,  "last_triggered":"2026-02-23 14:00"},
    {"id":"RAN-005","name":"Mass File Read — Exfil",      "risk_level":"High",    "pattern":"read.*\\.(docx|xlsx|pdf).*1000/s","enabled":True,"last_triggered":None},
    {"id":"RAN-006","name":"Cobalt Strike Beacon",        "risk_level":"Critical","pattern":"cobaltstrike.*beacon.*https","enabled":True,  "last_triggered":None},
    {"id":"RAN-007","name":"WannaCry SMB Exploit",        "risk_level":"Critical","pattern":"ms17-010.*smb.*exploit",    "enabled":False, "last_triggered":"2026-01-10 11:00"},
]

for r in RAN_RULES:
    if not db.query(RansomwareRule).filter(RansomwareRule.id == r["id"]).first():
        db.add(RansomwareRule(**r))

# ── Anomaly Config ─────────────────────────────────────
if not db.query(AnomalyConfig).filter(AnomalyConfig.id == 1).first():
    db.add(AnomalyConfig(
        id=1, enabled=True, sensitivity="Medium",
        baseline_window=300, packet_size_mult=3.0,
        conn_rate_mult=5.0, dns_query_rate=100,
        traffic_volume_mult=10.0, alert_cooldown=60,
    ))

# ── Network Interfaces ─────────────────────────────────
IFACES = [
    {"name":"eth0", "mode":"Monitor", "enabled":True,  "speed":"1 Gbps",  "ip_address":"192.168.1.10"},
    {"name":"eth1", "mode":"Inline",  "enabled":True,  "speed":"1 Gbps",  "ip_address":"192.168.1.11"},
    {"name":"eth2", "mode":"Monitor", "enabled":False, "speed":"10 Gbps", "ip_address":None},
]
for iface in IFACES:
    if not db.query(NetworkInterface).filter(NetworkInterface.name == iface["name"]).first():
        db.add(NetworkInterface(**iface))

# ── Alert Settings ─────────────────────────────────────
if not db.query(AlertSettings).filter(AlertSettings.id == 1).first():
    db.add(AlertSettings(
        id=1, email_enabled=True,
        email_recipients=["soc@cyguardian.local","admin@cyguardian.local"],
        sms_enabled=False, sms_numbers=[],
        webhook_enabled=False, webhook_url=None,
        min_severity="High",
    ))

# ── System Settings ────────────────────────────────────
if not db.query(SystemSettings).filter(SystemSettings.id == 1).first():
    db.add(SystemSettings(
        id=1, log_retention_days=90, max_packet_capture=10000,
        performance_mode="Balanced", auto_block_enabled=False,
        auto_block_threshold=100,
    ))

db.commit()
db.close()
print("✅ Configuration seed complete.")