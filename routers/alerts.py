import os
import json
import glob
from fastapi import APIRouter

router = APIRouter()

@router.get("/alerts")
def get_alerts():
    """
    Returns recent HIGH/CRITICAL risk detections as a real-time alert feed
    for bank dashboards and security teams.
    """
    alerts = []
    report_files = sorted(
        glob.glob("threat_reports/*_static_report.json"),
        key=os.path.getmtime,
        reverse=True
    )

    for path in report_files[:20]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            verdict = data.get("verdict", "")
            if verdict not in ["HIGH", "CRITICAL"]:
                continue

            osint_flags = data.get("threat_intelligence", {}).get("osint_flags", [])
            perm_flags = data.get("threat_intelligence", {}).get("permission_flags", [])
            top_flag = osint_flags[0] if osint_flags else (
                perm_flags[0].get("signal", "") if perm_flags else "No flags"
            )

            alerts.append({
                "package_id": data.get("package_id"),
                "app_name": data.get("playstore_name") or "Sideloaded Ghost App",
                "developer": data.get("developer") or "Unknown",
                "verdict": verdict,
                "risk_score": data.get("risk_breakdown", {}).get("final_composite_score", 0),
                "top_flag": top_flag,
                "permission_violations": len(perm_flags),
                "report_url": f"/api/v1/report/dynamic/{data.get('package_id')}",
                "pdf_url": f"/api/v1/report/pdf/{data.get('package_id')}",
            })
        except Exception:
            continue

    return {
        "total_high_risk_detections": len(alerts),
        "alerts": alerts,
        "note": "Showing most recent HIGH and CRITICAL risk detections only."
    }