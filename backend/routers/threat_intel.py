import os
import requests
from fastapi import APIRouter, Query, HTTPException

router = APIRouter(prefix="/api/threat-intel", tags=["Threat Intel"])


@router.get("/abuseipdb")
def abuseipdb_lookup(ip: str = Query(..., description="IPv4/IPv6 to check")):
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="ABUSEIPDB_API_KEY not configured")

    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=12,
        )
        return {"provider": "abuseipdb", "ok": r.ok, "status": r.status_code, "data": r.json()}
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"AbuseIPDB request failed: {str(e)}")


@router.get("/virustotal/ip")
def virustotal_ip_lookup(ip: str = Query(..., description="IPv4/IPv6 to check")):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="VIRUSTOTAL_API_KEY not configured")

    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": api_key},
            timeout=12,
        )
        return {"provider": "virustotal", "ok": r.ok, "status": r.status_code, "data": r.json()}
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"VirusTotal request failed: {str(e)}")


@router.get("/geoip")
def geoip_lookup(ip: str = Query(..., description="IPv4/IPv6 to check")):
    # free source, no key
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        return {"provider": "ip-api", "ok": r.ok, "status": r.status_code, "data": r.json()}
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"GeoIP request failed: {str(e)}")


@router.get("/enrich")
def enrich_ip(ip: str = Query(..., description="IPv4/IPv6 to enrich")):
    """
    Unified endpoint for frontend:
    returns reputation + geo info in one response.
    VirusTotal/AbuseIPDB are optional (if keys exist).
    """
    result = {"ip": ip, "abuseipdb": None, "virustotal": None, "geoip": None}

    # AbuseIPDB (optional)
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    if abuse_key:
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": abuse_key, "Accept": "application/json"},
                timeout=10,
            )
            result["abuseipdb"] = r.json()
        except Exception:
            result["abuseipdb"] = {"error": "failed"}

    # VirusTotal (optional)
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    if vt_key:
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": vt_key},
                timeout=10,
            )
            result["virustotal"] = r.json()
        except Exception:
            result["virustotal"] = {"error": "failed"}

    # GeoIP (free)
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=8)
        result["geoip"] = r.json()
    except Exception:
        result["geoip"] = {"error": "failed"}

    return result