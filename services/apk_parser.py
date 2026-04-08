import os
from pyaxmlparser import APK

# RBI 2025 Digital Lending Directions - Hard Rules
CRITICAL_VIOLATIONS = [
    'android.permission.READ_CONTACTS',
    'android.permission.READ_CALL_LOG',
    'android.permission.READ_MEDIA_IMAGES',
    'android.permission.READ_EXTERNAL_STORAGE',
    'android.permission.WRITE_EXTERNAL_STORAGE'
]

SUSPICIOUS_INDICATORS = [
    'android.permission.READ_SMS', # Legit apps should use SMS Retriever API
    'android.permission.RECEIVE_SMS',
    'android.permission.ACCESS_FINE_LOCATION' # Only one-time KYC access is allowed
]

def parse_apk_manifest(apk_filepath):
    """
    Extracts permissions from an APK and checks against RBI guidelines.
    """
    if not os.path.exists(apk_filepath):
        return {"status": "error", "message": "APK file not found"}

    try:
        apk = APK(apk_filepath)
        
        package_id = apk.package
        app_name = apk.application
        permissions = apk.get_declared_permissions()

        violation_flags = []
        regulatory_risk_score = 0.0

        for perm in permissions:
            if perm in CRITICAL_VIOLATIONS:
                violation_flags.append({
                    "signal": f"Critical RBI Violation: {perm.split('.')[-1]}", 
                    "weight": 0.40
                })
                regulatory_risk_score += 0.40
            
            elif perm in SUSPICIOUS_INDICATORS:
                violation_flags.append({
                    "signal": f"Suspicious Permission: {perm.split('.')[-1]}", 
                    "weight": 0.15
                })
                regulatory_risk_score += 0.15

        return {
            "status": "success",
            "package_id": package_id,
            "app_name": app_name,
            "raw_permissions": permissions,
            "violation_flags": violation_flags,
            "regulatory_risk_score": min(regulatory_risk_score, 1.0) # Cap at 1.0
        }

    except Exception as e:
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    # Drop a dummy APK in your data folder to test this locally
    # print(parse_apk_manifest("../data/test_app.apk"))
    pass