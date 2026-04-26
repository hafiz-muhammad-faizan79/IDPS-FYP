# idps-backend/seed_incidents.py
from database import SessionLocal, engine, Base
from models.incident import Incident, Detection, IncidentTimeline, DetectionIPAction

Base.metadata.create_all(bind=engine)
db = SessionLocal()

# ── Incidents ──────────────────────────────────────────
INCIDENTS = [
    {"id":"INC-001","desc":"SYN flood targeting web server port 443",           "type":"DDoS",        "severity":"Critical","status":"Open",       "analyst":"analyst1", "src_ip":"185.220.101.47","dst_ip":"10.0.0.15", "protocol":"TCP", "port":443,  "timestamp":"2026-02-24 08:55"},
    {"id":"INC-002","desc":"Repeated SSH login failures from external IP",      "type":"Brute Force", "severity":"High",    "status":"In Progress","analyst":"soc_lead", "src_ip":"91.108.4.200",  "dst_ip":"10.0.0.22", "protocol":"TCP", "port":22,   "timestamp":"2026-02-24 07:30"},
    {"id":"INC-003","desc":"SQL injection attempt on login endpoint",           "type":"Signature",   "severity":"Critical","status":"Open",       "analyst":"analyst2", "src_ip":"103.75.190.12", "dst_ip":"10.0.0.5",  "protocol":"HTTP","port":80,   "timestamp":"2026-02-24 08:40"},
    {"id":"INC-004","desc":"LockBit C2 beacon detected on port 8443",          "type":"Ransomware",  "severity":"Critical","status":"Open",       "analyst":"admin",    "src_ip":"77.83.246.90",  "dst_ip":"10.0.0.8",  "protocol":"TCP", "port":8443, "timestamp":"2026-02-24 09:00"},
    {"id":"INC-005","desc":"Anomalous outbound traffic spike — 3x baseline",   "type":"Anomaly",     "severity":"High",    "status":"In Progress","analyst":"analyst1", "src_ip":"10.0.0.44",     "dst_ip":"8.8.8.8",   "protocol":"UDP", "port":53,   "timestamp":"2026-02-24 07:55"},
    {"id":"INC-006","desc":"Port scan detected across /24 subnet",             "type":"Signature",   "severity":"Medium",  "status":"Resolved",   "analyst":"analyst2", "src_ip":"45.142.212.100","dst_ip":"10.0.0.0",  "protocol":"TCP", "port":0,    "timestamp":"2026-02-23 22:10"},
    {"id":"INC-007","desc":"Shadow copy deletion via vssadmin command",        "type":"Ransomware",  "severity":"Critical","status":"Open",       "analyst":"soc_lead", "src_ip":"10.0.0.31",     "dst_ip":"10.0.0.100","protocol":"SMB", "port":445,  "timestamp":"2026-02-24 08:50"},
    {"id":"INC-008","desc":"XSS payload in user-agent header",                 "type":"Signature",   "severity":"Medium",  "status":"Resolved",   "analyst":"analyst1", "src_ip":"162.247.74.200","dst_ip":"10.0.0.5",  "protocol":"HTTP","port":80,   "timestamp":"2026-02-23 20:00"},
    {"id":"INC-009","desc":"UDP amplification attack — 921K packets/sec",      "type":"DDoS",        "severity":"Critical","status":"In Progress","analyst":"admin",    "src_ip":"194.165.16.78", "dst_ip":"10.0.0.1",  "protocol":"UDP", "port":123,  "timestamp":"2026-02-24 08:45"},
    {"id":"INC-010","desc":"Emotet malware C2 communication pattern",          "type":"Signature",   "severity":"High",    "status":"Open",       "analyst":"analyst2", "src_ip":"5.188.206.14",  "dst_ip":"10.0.0.19", "protocol":"HTTP","port":8080, "timestamp":"2026-02-24 08:10"},
    {"id":"INC-011","desc":"Mass read of /home directories — possible exfil",  "type":"Ransomware",  "severity":"High",    "status":"In Progress","analyst":"soc_lead", "src_ip":"10.0.0.55",     "dst_ip":"10.0.0.200","protocol":"NFS", "port":2049, "timestamp":"2026-02-24 07:40"},
    {"id":"INC-012","desc":"Baseline traffic anomaly — packet size >3x avg",   "type":"Anomaly",     "severity":"Low",     "status":"Closed",     "analyst":"analyst1", "src_ip":"10.0.0.77",     "dst_ip":"10.0.0.1",  "protocol":"TCP", "port":443,  "timestamp":"2026-02-23 16:00"},
    {"id":"INC-013","desc":"Ryuk-style registry key modification detected",    "type":"Ransomware",  "severity":"Critical","status":"Open",       "analyst":"admin",    "src_ip":"10.0.0.31",     "dst_ip":"10.0.0.100","protocol":"RPC", "port":135,  "timestamp":"2026-02-24 08:52"},
    {"id":"INC-014","desc":"FTP brute force — 2,400 attempts in 10 minutes",   "type":"Brute Force", "severity":"Medium",  "status":"Resolved",   "analyst":"analyst2", "src_ip":"91.108.4.200",  "dst_ip":"10.0.0.22", "protocol":"FTP", "port":21,   "timestamp":"2026-02-23 12:00"},
    {"id":"INC-015","desc":"DNS tunneling pattern — covert data exfiltration", "type":"Anomaly",     "severity":"High",    "status":"Open",       "analyst":"soc_lead", "src_ip":"10.0.0.44",     "dst_ip":"185.1.1.1", "protocol":"DNS", "port":53,   "timestamp":"2026-02-24 08:30"},
]
for r in INCIDENTS:
    if not db.query(Incident).filter(Incident.id == r["id"]).first():
        db.add(Incident(**r))

# ── Detections ─────────────────────────────────────────
DETECTIONS = [
    {"id":1,  "timestamp":"2026-02-24 09:12","src_ip":"185.220.101.47","dst_ip":"10.0.0.15", "protocol":"TCP", "port":443,  "det_type":"Anomaly",   "severity":"Critical","classification":"Malicious",  "explanation":"Traffic volume 50x baseline — DDoS pattern confirmed"},
    {"id":2,  "timestamp":"2026-02-24 09:10","src_ip":"103.75.190.12", "dst_ip":"10.0.0.5",  "protocol":"HTTP","port":80,   "det_type":"Signature", "severity":"Critical","classification":"Malicious",  "explanation":"SQL UNION SELECT payload matched SIG-001"},
    {"id":3,  "timestamp":"2026-02-24 09:08","src_ip":"77.83.246.90",  "dst_ip":"10.0.0.8",  "protocol":"TCP", "port":8443, "det_type":"Ransomware","severity":"Critical","classification":"Malicious",  "explanation":"LockBit C2 beacon pattern on non-standard port"},
    {"id":4,  "timestamp":"2026-02-24 09:05","src_ip":"91.108.4.200",  "dst_ip":"10.0.0.22", "protocol":"TCP", "port":22,   "det_type":"Signature", "severity":"High",    "classification":"Suspicious", "explanation":"SSH brute force — 847 failed attempts in 5 minutes"},
    {"id":5,  "timestamp":"2026-02-24 09:01","src_ip":"10.0.0.31",     "dst_ip":"10.0.0.100","protocol":"SMB", "port":445,  "det_type":"Ransomware","severity":"Critical","classification":"Malicious",  "explanation":"vssadmin shadow copy deletion — Ryuk indicator"},
    {"id":6,  "timestamp":"2026-02-24 08:58","src_ip":"194.165.16.78", "dst_ip":"10.0.0.1",  "protocol":"UDP", "port":123,  "det_type":"Anomaly",   "severity":"Critical","classification":"Malicious",  "explanation":"UDP amplification — 921K pps from known bad actor"},
    {"id":7,  "timestamp":"2026-02-24 08:55","src_ip":"10.0.0.44",     "dst_ip":"8.8.8.8",   "protocol":"DNS", "port":53,   "det_type":"Anomaly",   "severity":"High",    "classification":"Suspicious", "explanation":"Unusually high DNS query rate — possible tunneling"},
    {"id":8,  "timestamp":"2026-02-24 08:50","src_ip":"45.142.212.100","dst_ip":"10.0.0.0",  "protocol":"TCP", "port":0,    "det_type":"Signature", "severity":"Medium",  "classification":"Suspicious", "explanation":"NMAP SYN scan across /24 — 254 hosts probed"},
    {"id":9,  "timestamp":"2026-02-24 08:44","src_ip":"5.188.206.14",  "dst_ip":"10.0.0.19", "protocol":"HTTP","port":8080, "det_type":"Signature", "severity":"High",    "classification":"Malicious",  "explanation":"Emotet dropper URL pattern in HTTP payload"},
    {"id":10, "timestamp":"2026-02-24 08:40","src_ip":"162.247.74.200","dst_ip":"10.0.0.5",  "protocol":"HTTP","port":80,   "det_type":"Signature", "severity":"Medium",  "classification":"Suspicious", "explanation":"XSS payload detected in User-Agent header"},
    {"id":11, "timestamp":"2026-02-24 08:35","src_ip":"10.0.0.55",     "dst_ip":"10.0.0.200","protocol":"NFS", "port":2049, "det_type":"Ransomware","severity":"High",    "classification":"Suspicious", "explanation":"Mass file read across /home — 1,200 reads/sec"},
    {"id":12, "timestamp":"2026-02-24 08:30","src_ip":"10.0.0.77",     "dst_ip":"10.0.0.1",  "protocol":"TCP", "port":443,  "det_type":"Anomaly",   "severity":"Low",     "classification":"Suspicious", "explanation":"Packet size 3x above moving average baseline"},
    {"id":13, "timestamp":"2026-02-24 08:20","src_ip":"91.108.4.200",  "dst_ip":"10.0.0.22", "protocol":"FTP", "port":21,   "det_type":"Signature", "severity":"Medium",  "classification":"Suspicious", "explanation":"FTP login failures — 2,400 attempts over 10 minutes"},
    {"id":14, "timestamp":"2026-02-24 08:10","src_ip":"10.0.0.31",     "dst_ip":"10.0.0.100","protocol":"RPC", "port":135,  "det_type":"Ransomware","severity":"Critical","classification":"Malicious",  "explanation":"Ryuk registry key write to HKLM\\SOFTWARE\\Microsoft\\Windows"},
    {"id":15, "timestamp":"2026-02-24 07:55","src_ip":"203.0.113.9",   "dst_ip":"10.0.0.5",  "protocol":"HTTP","port":80,   "det_type":"Signature", "severity":"High",    "classification":"Malicious",  "explanation":"Blind SQL injection time-delay pattern detected"},
    {"id":16, "timestamp":"2026-02-24 07:40","src_ip":"10.0.0.44",     "dst_ip":"185.1.1.1", "protocol":"DNS", "port":53,   "det_type":"Anomaly",   "severity":"High",    "classification":"Suspicious", "explanation":"Long DNS subdomain queries — covert channel indicator"},
    {"id":17, "timestamp":"2026-02-24 07:30","src_ip":"185.220.101.47","dst_ip":"10.0.0.15", "protocol":"TCP", "port":80,   "det_type":"Anomaly",   "severity":"Medium",  "classification":"Suspicious", "explanation":"Connection rate 8x baseline from single source"},
    {"id":18, "timestamp":"2026-02-24 07:15","src_ip":"10.0.0.12",     "dst_ip":"10.0.0.50", "protocol":"TCP", "port":3389, "det_type":"Signature", "severity":"Low",     "classification":"Normal",     "explanation":"RDP connection within policy — informational log"},
    {"id":19, "timestamp":"2026-02-24 07:00","src_ip":"198.51.100.7",  "dst_ip":"10.0.0.22", "protocol":"TCP", "port":22,   "det_type":"Signature", "severity":"Info",    "classification":"Normal",     "explanation":"SSH login from known admin IP — policy compliant"},
    {"id":20, "timestamp":"2026-02-24 06:45","src_ip":"10.0.0.100",    "dst_ip":"10.0.0.200","protocol":"TCP", "port":443,  "det_type":"Anomaly",   "severity":"Low",     "classification":"Normal",     "explanation":"Minor traffic deviation — within acceptable threshold"},
]
for r in DETECTIONS:
    if not db.query(Detection).filter(Detection.id == r["id"]).first():
        db.add(Detection(**r))

# ── Timelines (4 events per incident) ─────────────────
TIMELINES = [
    ("INC-001",[("08:55","Incident created — automated detection triggered"),("09:00","Alert escalated to SOC analyst"),("09:05","Initial triage completed — confirmed threat"),("09:10","Containment action initiated — IP flagged for blocking")]),
    ("INC-002",[("07:30","Incident created — brute force threshold exceeded"),("07:45","Assigned to soc_lead for investigation"),("08:00","Source IP geolocated — known threat actor"),("08:44","Active monitoring — further attempts ongoing")]),
    ("INC-003",[("08:40","SQL injection detected by SIG-001"),("08:45","Web application firewall rule triggered"),("08:55","Developer team notified"),("09:01","Patch deployment in progress")]),
    ("INC-004",[("09:00","LockBit C2 beacon first detected"),("09:02","Network segment isolated"),("09:05","Ransomware response team activated"),("09:08","Threat contained — full scan initiated")]),
]
for inc_id, events in TIMELINES:
    for time, event in events:
        if not db.query(IncidentTimeline).filter(
            IncidentTimeline.incident_id == inc_id,
            IncidentTimeline.event == event
        ).first():
            db.add(IncidentTimeline(incident_id=inc_id, time=time, event=event))

db.commit()
db.close()
print("✅ Incidents seed complete.")