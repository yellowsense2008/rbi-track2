from ml.anomaly import detect_anomaly

KNOWN_LEGITIMATE_BANKS = [
    "state bank of india", "sbi", "hdfc bank", "icici bank",
    "axis bank", "kotak mahindra", "punjab national bank", "pnb",
    "bank of baroda", "canara bank", "union bank", "indusind bank",
    "yes bank", "idfc first", "federal bank", "rbl bank",
    "google pay", "phonepe", "paytm", "amazon pay", "bhim"
]

WEIGHTS = {
    "not_in_dla_registry":        0.30,
    "not_in_nbfc_registry":       0.20,
    "claims_rbi":                 0.20,
    "impersonation":              0.15,
    "harvests_data":              0.10,
    "reads_sms":                  0.05,
    "free_email":                 0.05,
    "domain_age_flag":            0.05,
    "suspicious_rating":          0.05,
    "urgency_language":           0.05,
    "thin_description":           0.03,
    "low_installs":               0.03,
    "no_ratings":                 0.02,
}

def is_known_legitimate_bank(app_meta: dict) -> bool:
    title = (app_meta.get("title") or "").lower()
    developer = (app_meta.get("developer") or "").lower()
    for bank in KNOWN_LEGITIMATE_BANKS:
        if bank in title or bank in developer:
            return True
    return False

def is_finance_app(app_meta: dict, features: dict) -> bool:
    return features.get("title_has_loan", 0) == 1 or \
           (app_meta.get("genre") or "").lower() == "finance"

def build_explanation(app_name: str, verdict: str, flagged_reasons: list) -> str:
    if verdict == "LOW":
        return f"{app_name} appears legitimate. No significant risk signals detected."
    
    if verdict == "MEDIUM":
        signals = ", ".join([r["signal"] for r in flagged_reasons[:2]])
        return (f"{app_name} shows moderate risk. "
                f"Key concerns: {signals}. "
                f"Verify on RBI's official DLA directory before use.")
    
    # HIGH
    top_signals = [r["signal"] for r in flagged_reasons[:3]]
    signals_text = "; ".join(top_signals)
    return (f"WARNING: {app_name} is HIGH risk. "
            f"Critical violations: {signals_text}. "
            f"This app is NOT in RBI's authorized lending app registry. "
            f"Do not download or share financial information.")

def compute_risk_score(app_meta: dict, features: dict) -> dict:
    # Known legitimate bank — auto LOW
    if is_known_legitimate_bank(app_meta):
        return {
            "risk_score": 0.05,
            "verdict": "LOW",
            "flagged_reasons": [],
            "is_finance_app": True,
            "note": "Known legitimate bank/payment app"
        }

    # Not a finance app — auto LOW
    if not is_finance_app(app_meta, features):
        return {
            "risk_score": 0.02,
            "verdict": "LOW",
            "flagged_reasons": [],
            "is_finance_app": False,
            "note": "Not a finance app"
        }

    flagged = []
    score = 0.0

    # DLA registry check
    if not features.get("in_dla_registry"):
        score += WEIGHTS["not_in_dla_registry"]
        flagged.append({
            "signal": "Not in RBI DLA Registry",
            "detail": "App not found in RBI's official Digital Lending Apps directory",
            "weight": WEIGHTS["not_in_dla_registry"]
        })

    # NBFC registry check
    if not features.get("is_registered"):
        score += WEIGHTS["not_in_nbfc_registry"]
        flagged.append({
            "signal": "Developer not in NBFC Registry",
            "detail": f"Developer not found as registered NBFC with RBI",
            "weight": WEIGHTS["not_in_nbfc_registry"]
        })

    # Claims RBI approval
    if features.get("claims_rbi"):
        score += WEIGHTS["claims_rbi"]
        flagged.append({
            "signal": "False RBI Approval Claim",
            "detail": "Description contains fraudulent RBI approval claims",
            "weight": WEIGHTS["claims_rbi"]
        })

    # Impersonation
    if features.get("impersonation"):
        score += WEIGHTS["impersonation"]
        flagged.append({
            "signal": "Bank Impersonation Detected",
            "detail": "App claims association with known bank but developer doesn't match",
            "weight": WEIGHTS["impersonation"]
        })

    # Data harvesting
    if features.get("harvests_data"):
        score += WEIGHTS["harvests_data"]
        flagged.append({
            "signal": "Excessive Data Harvesting",
            "detail": "Requests both SMS and Contacts permissions — classic predatory pattern",
            "weight": WEIGHTS["harvests_data"]
        })

    # SMS permission
    if features.get("reads_sms") and not features.get("harvests_data"):
        score += WEIGHTS["reads_sms"]
        flagged.append({
            "signal": "SMS Access Permission",
            "detail": "Requests SMS read permission — unusual for legitimate lenders",
            "weight": WEIGHTS["reads_sms"]
        })

    # Free email
    if features.get("free_email"):
        score += WEIGHTS["free_email"]
        flagged.append({
            "signal": "Non-Corporate Developer Email",
            "detail": "Developer uses free email (Gmail/Yahoo) instead of corporate domain",
            "weight": WEIGHTS["free_email"]
        })

    # Domain age
    if features.get("domain_age_flag"):
        score += WEIGHTS["domain_age_flag"]
        flagged.append({
            "signal": "New Domain",
            "detail": "Developer website domain registered less than 90 days ago",
            "weight": WEIGHTS["domain_age_flag"]
        })

    # Suspicious rating
    if features.get("suspicious_rating"):
        score += WEIGHTS["suspicious_rating"]
        flagged.append({
            "signal": "Suspicious Rating Pattern",
            "detail": "High rating with very low install count — possible fake reviews",
            "weight": WEIGHTS["suspicious_rating"]
        })

    # Urgency language
    if features.get("urgency_language"):
        score += WEIGHTS["urgency_language"]
        flagged.append({
            "signal": "Predatory Language",
            "detail": "Description uses urgency/guaranteed approval language",
            "weight": WEIGHTS["urgency_language"]
        })

    # Thin description
    if features.get("thin_description"):
        score += WEIGHTS["thin_description"]
        flagged.append({
            "signal": "Thin App Description",
            "detail": "Very short description — lacks transparency expected of regulated lenders",
            "weight": WEIGHTS["thin_description"]
        })

    # Low installs
    if features.get("low_installs"):
        score += WEIGHTS["low_installs"]
        flagged.append({
            "signal": "Very Low Install Count",
            "detail": "Fewer than 1,000 installs — new or suspicious app",
            "weight": WEIGHTS["low_installs"]
        })

    # No ratings
    if features.get("no_ratings"):
        score += WEIGHTS["no_ratings"]
        flagged.append({
            "signal": "No User Ratings",
            "detail": "Fewer than 10 ratings — unverified by users",
            "weight": WEIGHTS["no_ratings"]
        })

    # Clamp to 1.0
    score = min(round(score, 3), 1.0)

    # Verdict
    if score >= 0.60:
        verdict = "HIGH"
    elif score >= 0.30:
        verdict = "MEDIUM"
    else:
        verdict = "LOW"

    # Anomaly detection
    anomaly_result = detect_anomaly(
        installs=app_meta.get("installs") or 0,
        rating=app_meta.get("score") or 0,
        ratings_count=app_meta.get("ratings") or 0,
        description_length=len((app_meta.get("description") or ""))
    )
    if anomaly_result["is_anomaly"] and is_finance_app(app_meta, features):
        score = min(score + 0.10, 1.0)
        flagged.append({
            "signal": "Statistical Anomaly Detected",
            "detail": f"App metadata pattern is statistically suspicious (score: {anomaly_result['anomaly_score']})",
            "weight": 0.10
        })

    return {
        "risk_score": score,
        "verdict": verdict,
        "flagged_reasons": flagged,
        "is_finance_app": True,
        "note": build_explanation(
                app_meta.get("title", "This app"),
                verdict,
                flagged
            )
    }