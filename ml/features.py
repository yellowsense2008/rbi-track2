import re
import numpy as np
# Add this import at the top
from services.dla_registry import lookup_dla_by_app_id

DANGEROUS_PERMISSIONS = [
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.GET_ACCOUNTS",
]

KNOWN_BANKS = {
    "sbi": "State Bank of India",
    "hdfc": "HDFC Bank",
    "icici": "ICICI Bank",
    "axis": "Axis Bank",
    "kotak": "Kotak Mahindra Bank",
    "paytm": "Paytm Payments Bank",
    "rbi": None,
    "reserve bank": None,
    "npci": None,
}

RBI_FRAUD_PHRASES = [
    "rbi approved", "rbi registered", "rbi certified",
    "reserve bank approved", "guaranteed loan", "instant approval",
    "no credit check", "100% approval", "aadhar loan",
    "loan without documents", "instant cash", "same day loan",
]

def extract_features(app_meta: dict, registry_result: dict, domain_result: dict) -> dict:
    title = (app_meta.get("title") or "").lower()
    description = (app_meta.get("description") or "").lower()
    developer = (app_meta.get("developer") or "").lower()
    email = (app_meta.get("developer_email") or "")
    installs = app_meta.get("installs") or 0
    score = app_meta.get("score") or 0
    ratings = app_meta.get("ratings") or 0
    permissions = app_meta.get("permissions") or []

    # Feature 1: NBFC registry
    is_registered = 1 if registry_result.get("found") else 0

    # Feature 2: Domain age
    domain_age = domain_result.get("domain_age_days", -1)
    domain_age_flag = 1 if (domain_age != -1 and domain_age < 90) else 0

    # Feature 3: Dangerous permissions count
    dangerous_count = sum(
        1 for p in permissions if p in DANGEROUS_PERMISSIONS
    )

    # Feature 4: SMS permission (high risk for loan apps)
    reads_sms = 1 if any(
        "SMS" in p for p in permissions
    ) else 0

    # Feature 5: Contacts + SMS together (classic data harvesting combo)
    harvests_data = 1 if (
        any("SMS" in p for p in permissions) and
        any("CONTACTS" in p for p in permissions)
    ) else 0

    # Feature 6: Claims RBI approval in description
    claims_rbi = 1 if any(
        phrase in description for phrase in RBI_FRAUD_PHRASES
    ) else 0

    # Feature 7: Impersonation — claims to be a known bank but wrong developer
    impersonation = 0
    for keyword, official in KNOWN_BANKS.items():
        if keyword in title or keyword in description:
            if official is None:
                impersonation = 1
                break
            if official.lower() not in developer:
                impersonation = 1
                break

    # Feature 8: Suspicious rating pattern (high rating, very low installs)
    suspicious_rating = 1 if (score > 4.3 and installs < 5000) else 0

    # Feature 9: Very low installs absolute
    low_installs = 1 if installs < 1000 else 0

    # Feature 10: Developer uses free email (Gmail, Yahoo, etc.)
    free_email = 1 if any(
        domain in email.lower()
        for domain in ["gmail", "yahoo", "hotmail", "outlook"]
    ) else 0

    # Feature 11: Thin description (fake apps often have very short descriptions)
    thin_description = 1 if len(description) < 200 else 0

    # Feature 12: Description mentions loan + urgent language
    urgency_language = 1 if any(
        word in description
        for word in ["urgent", "immediately", "within minutes",
                     "no rejection", "guaranteed", "instant disbursal"]
    ) else 0

    # Feature 13: App title has bank/loan keyword
    title_has_loan = 1 if any(
        word in title
        for word in ["loan", "credit", "lending", "cash", "finance", "bank"]
    ) else 0

    # Feature 14: No ratings at all (brand new or fake)
    no_ratings = 1 if ratings < 10 else 0

    # Feature 15: Registry match score (continuous)
    registry_score = registry_result.get("score", 0)

    # Feature 16: Not in RBI DLA registry (strongest signal for lending apps)
    dla_result = lookup_dla_by_app_id(app_meta.get("app_id", ""))
    in_dla_registry = 1 if dla_result.get("found") else 0

    return {
        "is_registered": is_registered,
        "domain_age_flag": domain_age_flag,
        "dangerous_permission_count": dangerous_count,
        "reads_sms": reads_sms,
        "harvests_data": harvests_data,
        "claims_rbi": claims_rbi,
        "impersonation": impersonation,
        "suspicious_rating": suspicious_rating,
        "low_installs": low_installs,
        "free_email": free_email,
        "thin_description": thin_description,
        "urgency_language": urgency_language,
        "title_has_loan": title_has_loan,
        "no_ratings": no_ratings,
        "registry_score": registry_score,
        "in_dla_registry": in_dla_registry,
    }

# --- NEW ML PIPELINE ADDITIONS BELOW ---

# This master list MUST match the exact columns of the Kaggle CSV you will use for training
MASTER_PERMISSIONS = [
    'android.permission.INTERNET',
    'android.permission.ACCESS_NETWORK_STATE',
    'android.permission.ACCESS_WIFI_STATE',
    'android.permission.READ_PHONE_STATE',
    'android.permission.READ_CONTACTS',
    'android.permission.WRITE_CONTACTS',
    'android.permission.READ_CALL_LOG',
    'android.permission.WRITE_CALL_LOG',
    'android.permission.READ_SMS',
    'android.permission.RECEIVE_SMS',
    'android.permission.SEND_SMS',
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.ACCESS_COARSE_LOCATION',
    'android.permission.CAMERA',
    'android.permission.RECORD_AUDIO',
    'android.permission.READ_EXTERNAL_STORAGE',
    'android.permission.WRITE_EXTERNAL_STORAGE',
    'android.permission.RECEIVE_BOOT_COMPLETED',
    'android.permission.WAKE_LOCK',
    'android.permission.DISABLE_KEYGUARD',
    'android.permission.GET_TASKS',
    'android.permission.SYSTEM_ALERT_WINDOW',
    'android.permission.CHANGE_WIFI_STATE',
    'android.permission.CHANGE_NETWORK_STATE',
    'android.permission.GET_ACCOUNTS',
    'android.permission.MANAGE_ACCOUNTS',
    'android.permission.USE_CREDENTIALS',
    'android.permission.VIBRATE',
    'android.permission.BLUETOOTH',
    'android.permission.INSTALL_PACKAGES'
]

def create_permission_vector(extracted_permissions: list) -> np.ndarray:
    """
    Converts a list of raw manifest permissions from an APK into a binary feature vector.
    Returns a 2D numpy array suitable for XGBoost inference.
    """
    if not extracted_permissions:
        return np.zeros((1, len(MASTER_PERMISSIONS)), dtype=int)

    vector = np.zeros(len(MASTER_PERMISSIONS), dtype=int)
    
    for i, perm in enumerate(MASTER_PERMISSIONS):
        if perm in extracted_permissions:
            vector[i] = 1
            
    return vector.reshape(1, -1)    