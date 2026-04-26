# idps-backend/seed_audits.py
from database import SessionLocal, engine, Base
from models.audit import AuditLog, MaliciousIP

Base.metadata.create_all(bind=engine)
db = SessionLocal()

AUDIT_LOGS = [
    {"id":"AUD-015","timestamp":"2026-02-24 09:10","actor":"admin",   "change_type":"Modified", "target":"SIG-003 SYN Flood",       "action":"Action changed",       "details":"Alert to Drop",               "rolled_back":False},
    {"id":"AUD-014","timestamp":"2026-02-24 08:58","actor":"admin",   "change_type":"Enabled",  "target":"LockBit Network Pattern", "action":"Rule enabled",         "details":"Disabled to Active",          "rolled_back":False},
    {"id":"AUD-013","timestamp":"2026-02-24 08:30","actor":"soc_lead","change_type":"Modified", "target":"Anomaly Sensitivity",     "action":"Setting updated",      "details":"Medium to High",              "rolled_back":False},
    {"id":"AUD-012","timestamp":"2026-02-24 08:10","actor":"admin",   "change_type":"Created",  "target":"Custom-SSH-Geo-Block",    "action":"New rule created",     "details":"Severity High, Action Block", "rolled_back":False},
    {"id":"AUD-011","timestamp":"2026-02-24 07:45","actor":"analyst1","change_type":"Disabled", "target":"SIG-008 HTTP Slowloris",  "action":"Rule disabled",        "details":"Active to Inactive",          "rolled_back":False},
    {"id":"AUD-010","timestamp":"2026-02-24 07:00","actor":"admin",   "change_type":"Modified", "target":"AES Pattern Detection",   "action":"Risk level updated",   "details":"High to Critical",            "rolled_back":False},
    {"id":"AUD-009","timestamp":"2026-02-23 22:15","actor":"soc_lead","change_type":"Modified", "target":"Packet Size Threshold",   "action":"Threshold updated",    "details":"1200 to 1500 bytes",          "rolled_back":False},
    {"id":"AUD-008","timestamp":"2026-02-23 18:00","actor":"admin",   "change_type":"Created",  "target":"SIG-015 Stored XSS",      "action":"New signature created","details":"Severity High HTTP",          "rolled_back":False},
    {"id":"AUD-007","timestamp":"2026-02-23 14:30","actor":"analyst2","change_type":"Disabled", "target":"Legacy Ransomware Rule",  "action":"Rule disabled",        "details":"Marked as deprecated",        "rolled_back":False},
    {"id":"AUD-006","timestamp":"2026-02-23 10:00","actor":"admin",   "change_type":"Deleted",  "target":"SIG-OLD-001 Obsolete",    "action":"Rule deleted",         "details":"Rule ID retired permanently", "rolled_back":False},
    {"id":"AUD-005","timestamp":"2026-02-22 16:45","actor":"soc_lead","change_type":"Modified", "target":"Traffic Rate Threshold",  "action":"Threshold updated",    "details":"5000 to 10000 pps",           "rolled_back":False},
    {"id":"AUD-004","timestamp":"2026-02-22 12:00","actor":"admin",   "change_type":"Created",  "target":"Custom-DDoS-Rate-Limit",  "action":"Custom rule created",  "details":"Severity Critical Drop",      "rolled_back":False},
    {"id":"AUD-003","timestamp":"2026-02-22 09:30","actor":"analyst1","change_type":"Modified", "target":"Auto IP Blocking",        "action":"Toggle updated",       "details":"OFF to ON",                   "rolled_back":False},
    {"id":"AUD-002","timestamp":"2026-02-21 18:00","actor":"admin",   "change_type":"Enabled",  "target":"Firewall Integration",    "action":"Module enabled",       "details":"Integration activated",       "rolled_back":False},
    {"id":"AUD-001","timestamp":"2026-02-21 10:00","actor":"soc_lead","change_type":"Modified", "target":"Baseline Learning Period","action":"Setting updated",      "details":"6 hours to 24 hours",         "rolled_back":False},
]

MALICIOUS_IPS = [
    {"ip":"185.220.101.47","events":4821,"type":"Anomaly",   "avg_sev":"Critical","protocol":"TCP", "country":"Russia",     "last_seen":"2026-02-24 09:10"},
    {"ip":"194.165.16.78", "events":3912,"type":"Anomaly",   "avg_sev":"Critical","protocol":"UDP", "country":"Iran",       "last_seen":"2026-02-24 09:08"},
    {"ip":"103.75.190.12", "events":2244,"type":"Signature", "avg_sev":"High",    "protocol":"HTTP","country":"China",      "last_seen":"2026-02-24 09:01"},
    {"ip":"77.83.246.90",  "events":1987,"type":"Signature", "avg_sev":"High",    "protocol":"HTTP","country":"Germany",    "last_seen":"2026-02-24 09:05"},
    {"ip":"91.108.4.200",  "events":1543,"type":"Signature", "avg_sev":"High",    "protocol":"TCP", "country":"Ukraine",    "last_seen":"2026-02-24 08:44"},
    {"ip":"5.188.206.14",  "events":1102,"type":"Ransomware","avg_sev":"Critical","protocol":"TCP", "country":"Luxembourg", "last_seen":"2026-02-24 08:59"},
    {"ip":"45.142.212.100","events":891, "type":"Signature", "avg_sev":"Medium",  "protocol":"TCP", "country":"Netherlands","last_seen":"2026-02-24 08:44"},
    {"ip":"162.247.74.200","events":612, "type":"Anomaly",   "avg_sev":"Medium",  "protocol":"HTTP","country":"USA",        "last_seen":"2026-02-23 23:00"},
    {"ip":"203.0.113.9",   "events":488, "type":"Signature", "avg_sev":"High",    "protocol":"HTTP","country":"Brazil",     "last_seen":"2026-02-24 07:55"},
    {"ip":"198.51.100.7",  "events":204, "type":"Anomaly",   "avg_sev":"Low",     "protocol":"TCP", "country":"Unknown",    "last_seen":"2026-02-24 07:00"},
]

for r in AUDIT_LOGS:
    if not db.query(AuditLog).filter(AuditLog.id == r["id"]).first():
        db.add(AuditLog(**r))

for r in MALICIOUS_IPS:
    if not db.query(MaliciousIP).filter(MaliciousIP.ip == r["ip"]).first():
        db.add(MaliciousIP(**r))

db.commit()
db.close()
print("✅ Audits seed complete.")