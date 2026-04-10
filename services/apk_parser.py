import os

CRITICAL_VIOLATIONS = [
    'android.permission.READ_CONTACTS',
    'android.permission.WRITE_CONTACTS',
    'android.permission.READ_CALL_LOG',
    'android.permission.READ_MEDIA_IMAGES',
    'android.permission.READ_MEDIA_VIDEO',
    'android.permission.READ_MEDIA_AUDIO',
    'android.permission.READ_EXTERNAL_STORAGE',
    'android.permission.WRITE_EXTERNAL_STORAGE',
]

SUSPICIOUS_INDICATORS = [
    'android.permission.READ_SMS',
    'android.permission.RECEIVE_SMS',
    'android.permission.SEND_SMS',
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.ACCESS_COARSE_LOCATION',
]

def parse_apk_manifest(apk_filepath):
    if not os.path.exists(apk_filepath):
        return {"status": "error", "message": "APK file not found"}

    try:
        from pyaxmlparser import APK
        apk = APK(apk_filepath)

        package_id = apk.package
        app_name = apk.application

        # Use apk.permissions (uses-permission tags) not get_declared_permissions()
        permissions = list(apk.permissions) if hasattr(apk, 'permissions') else []

        violation_flags = []
        regulatory_risk_score = 0.0

        for perm in permissions:
            if perm in CRITICAL_VIOLATIONS:
                violation_flags.append({
                    "signal": f"Critical RBI Violation: {perm.split('.')[-1]}",
                    "detail": f"{perm} is explicitly prohibited by RBI Digital Lending Directions 2025",
                    "weight": 0.40
                })
                regulatory_risk_score += 0.40

            elif perm in SUSPICIOUS_INDICATORS:
                violation_flags.append({
                    "signal": f"Suspicious Permission: {perm.split('.')[-1]}",
                    "detail": f"{perm} — legitimate apps use SMS Retriever API instead",
                    "weight": 0.15
                })
                regulatory_risk_score += 0.15

        return {
            "status": "success",
            "package_id": package_id,
            "app_name": app_name,
            "raw_permissions": permissions,
            "total_permissions": len(permissions),
            "violation_flags": violation_flags,
            "regulatory_risk_score": min(regulatory_risk_score, 1.0)
        }

    except Exception as e:
        return {"status": "error", "message": str(e)}