import os
import requests
import uuid
import json
from pydantic import BaseModel
from fastapi import APIRouter, File, UploadFile, BackgroundTasks
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from services.apk_parser import parse_apk_manifest
from services.scraper import fetch_app_metadata, analyze_domain
from services.registry import lookup_nbfc, is_arc_killswitch
from ml.features import extract_features, create_permission_vector
from ml.anomaly import detect_anomaly
from services.classifier import predict_apk_risk
from services.nlp_analyzer import detect_brand_impersonation
from services.mobsf_sandbox import detonate_in_sandbox
from services.financial_tracker import extract_financial_arteries
from services.assetlink_verifier import verify_assetlinks
from services.kfs_scanner import scan_for_kfs_osint
from services.scorer import KNOWN_LEGITIMATE_BANKS, compute_risk_score, is_known_legitimate_bank
from services.dla_registry import lookup_dla_by_app_id

router = APIRouter()

# -------------------------------------------------------------------
# MODULE-LEVEL CONSTANTS — defined once, not recreated per request
# -------------------------------------------------------------------
SCHEDULED_BANKS = [
    "aubank", "au small finance", "au0101", "com.ausmallfinancebank",
    "sbi", "com.sbi", "hdfc", "com.hdfc", "icici", "com.icici",
    "axis", "com.axis", "kotak", "com.kotak", "pnb", "bankofbaroda",
    "canara", "unionbank", "indusind", "yesbank", "idfcfirst",
    "federalbank", "rblbank", "bandhan", "equitas", "ujjivan",
    "esaf", "suryoday", "utkarsh"
]

def is_scheduled_bank_app(package_id: str, app_name: str, developer: str) -> bool:
    check_text = f"{package_id} {app_name} {developer}".lower()
    return any(bank in check_text for bank in SCHEDULED_BANKS)


def _run_analysis_pipeline(temp_file_path: str, background_tasks: BackgroundTasks):
    """
    Single shared analysis pipeline used by both APK upload and link endpoints.
    Eliminates all code duplication.
    """
    nlp_score, osint_penalty, anomaly_score, feature_penalty = 0.0, 0.0, 0.0, 0.0
    nlp_flags, osint_flags = [], []
    analysis_engine = "Ghost App Detection Engine (Sideloaded APK)"
    custom_features = {}
    anomaly_result = {"is_anomaly": False, "interpretation": "N/A"}
    developer_website = ""
    domain_result = {"domain_age_days": -1}

    # 1. Extract APK Blueprint (Static Engine)
    parser_result = parse_apk_manifest(temp_file_path)
    if parser_result.get("status") == "error":
        os.remove(temp_file_path)
        return {"error": f"Failed to parse APK: {parser_result.get('message')}"}

    package_id = parser_result.get("package_id")
    if not package_id or package_id == "None":
        os.remove(temp_file_path)
        return {"error": "CRITICAL EVASION DETECTED: Malformed AndroidManifest. Package ID is intentionally hidden or corrupted."}

    # Cache check
    dynamic_report_path = f"threat_reports/{package_id}_dynamic_report.json"
    static_report_path = f"threat_reports/{package_id}_static_report.json"

    if os.path.exists(dynamic_report_path) and os.path.exists(static_report_path):
        os.remove(temp_file_path)
        try:
            with open(static_report_path, "r", encoding="utf-8") as f:
                saved_static_data = json.load(f)
        except Exception:
            saved_static_data = {}
        return {
            "message": "App already analyzed. Cached results available.",
            "package_id": package_id,
            "dynamic_sandbox_status": "COMPLETED",
            "fetch_dynamic_report_url": f"/api/v1/report/dynamic/{package_id}",
            "verdict": saved_static_data.get("verdict", "HIGH"),
            "risk_breakdown": saved_static_data.get("risk_breakdown", {}),
            "threat_intelligence": saved_static_data.get("threat_intelligence", {}),
            "engines_firing": saved_static_data.get("engines_firing", [])
        }

    # 2. XGBoost ML Engine
    feature_vector = create_permission_vector(parser_result.get("raw_permissions", []))
    ai_result = predict_apk_risk(feature_vector)
    ml_risk_score = ai_result.get("risk_score", 0.0)

    # 3. Play Store Scrape
    scraped_data = fetch_app_metadata(package_id)

    # Single authoritative bank check — no duplicate loops
    is_bank_app = is_scheduled_bank_app(
        package_id,
        scraped_data.get("title", "") or "",
        scraped_data.get("developer", "") or ""
    )

    if is_bank_app:
        parser_result["violation_flags"] = []
        parser_result["regulatory_risk_score"] = 0.0

    if not scraped_data.get("error") and scraped_data.get("title"):

        # 4. OSINT Domain Analysis
        developer_website = scraped_data.get("developer_website", "") or ""
        domain_result = analyze_domain(developer_website)
        domain_age_days = domain_result.get("domain_age_days", -1)

        if domain_age_days > 0 and domain_age_days < 90:
            osint_penalty = 0.20
            osint_flags.append(f"Domain registered only {domain_age_days} days ago.")
        elif domain_age_days == -1 and not is_bank_app:
            osint_penalty = 0.10
            osint_flags.append("No valid developer website provided.")

        # 5. Isolation Forest Anomaly Detection
        anomaly_result = detect_anomaly(
            installs=scraped_data.get("installs", 0),
            rating=scraped_data.get("score", 0.0),
            ratings_count=scraped_data.get("ratings", 0),
            description_length=len(scraped_data.get("description", ""))
        )
        if anomaly_result["is_anomaly"]:
            anomaly_score = 0.20

        # 6. Registry Check & Feature Extraction
        registry_result = lookup_nbfc(scraped_data.get("developer", ""))
        custom_features.update(extract_features(scraped_data, registry_result, domain_result))

        if custom_features.get("free_email") and custom_features.get("urgency_language"):
            feature_penalty += 0.15
        if custom_features.get("claims_rbi") and not custom_features.get("in_dla_registry"):
            feature_penalty += 0.30

        # Developer Fingerprinting — low complexity signal, low weight
        dev_email = scraped_data.get("developer_email", "").lower()
        free_providers = ["@gmail.com", "@yahoo.com", "@hotmail.com", "@outlook.com"]
        if any(provider in dev_email for provider in free_providers):
            feature_penalty += 0.10  # Low weight — easy for scammer to avoid
            custom_features["free_email_provider"] = True
            osint_flags.append(
                f"OSINT FINGERPRINT: Entity claims financial status but uses a free email ({dev_email})."
            )

        # Cryptographic AssetLinks Check — very high complexity, impossible to fake
        if developer_website and developer_website != "N/A" and not is_bank_app:
            asset_check = verify_assetlinks(developer_website, package_id)
            if asset_check["status"] == "failed":
                feature_penalty += 0.40
                custom_features["assetlinks_failed"] = True
                osint_flags.append(
                    f"CRYPTOGRAPHIC MISMATCH: The official domain ({developer_website}) "
                    f"does not authorize this app. High probability of stolen identity."
                )

        # KFS Transparency Check
        if not is_bank_app:
            kfs_result = scan_for_kfs_osint(scraped_data.get("description", ""), developer_website)
            if not kfs_result["compliant"]:
                feature_penalty += 0.20
                custom_features["kfs_missing"] = True
                osint_flags.append(kfs_result["flag"])

        # ARC Kill Switch — regulatory, ARCs cannot issue retail loans
        arc_check = is_arc_killswitch(scraped_data.get("developer", ""))
        if arc_check["is_arc"]:
            feature_penalty += 1.0
            custom_features["arc_violation"] = True
            osint_flags.append(
                f"REGULATORY KILL SWITCH: App claims affiliation with '{arc_check['matched_name']}'. "
                f"This entity is an Asset Reconstruction Company (ARC) and is legally prohibited "
                f"from issuing retail loans."
            )

        # 7. NLP Brand Impersonation Engine
        nlp_result = detect_brand_impersonation(
            app_title=scraped_data.get("title", ""),
            developer_name=scraped_data.get("developer", ""),
            description=scraped_data.get("description", "")
        )
        nlp_score = nlp_result.get("nlp_risk_score", 0.0)
        nlp_flags = [f["signal"] for f in nlp_result.get("nlp_flags", [])]
        analysis_engine = nlp_result.get("engine_used", "Unknown")

    else:
        nlp_flags.append("Unverified Distribution: App is not on the Play Store.")
        nlp_score += 0.40

    # Ghost App Kill Switch
    if not scraped_data.get("developer") and not scraped_data.get("playstore_name"):
        if not is_bank_app:
            feature_penalty += 0.60
            custom_features["unverified_distribution"] = True
            custom_features["kfs_missing"] = True
            osint_flags.append(
                "CRITICAL: App is a 'Ghost'. Not found on official stores. "
                "Bypasses standard regulatory transparency. Massive risk of sideloaded malware."
            )

    # 8. Trust Override
    developer_name = scraped_data.get("developer") or ""
    is_trusted_entity = "bank" in developer_name.lower() or custom_features.get("in_dla_registry") == 1

    if ml_risk_score < 0.10 and is_trusted_entity and not custom_features.get("arc_violation"):
        feature_penalty = feature_penalty * 0.2
        osint_penalty = 0.0
        anomaly_score = 0.0
        osint_flags.append(
            "TRUST OVERRIDE: Entity recognized as legitimate financial institution. "
            "Heuristic penalties suppressed."
        )

    final_score = min(ml_risk_score + nlp_score + osint_penalty + anomaly_score + feature_penalty, 1.0)
    final_verdict = "HIGH" if final_score >= 0.60 else "MEDIUM" if final_score >= 0.30 else "LOW"

    # 9. Trigger Dynamic Sandbox
    background_tasks.add_task(detonate_in_sandbox, temp_file_path, package_id)

    # 10. Build Response
    final_response = {
        "package_id": package_id,
        "playstore_name": scraped_data.get("title", "N/A"),
        "developer": scraped_data.get("developer", "Unknown"),
        "verdict": final_verdict,
        "dynamic_sandbox_status": "DETONATING_IN_BACKGROUND",
        "risk_breakdown": {
            "ml_binary_risk": round(ml_risk_score, 3),
            "nlp_semantic_risk": round(nlp_score, 3),
            "osint_domain_risk": round(osint_penalty, 3),
            "anomaly_risk": round(anomaly_score, 3),
            "custom_feature_penalty": round(feature_penalty, 3),
            "final_composite_score": round(final_score, 3)
        },
        "threat_intelligence": {
            "permission_flags": parser_result.get("violation_flags", []),
            "impersonation_flags": nlp_flags,
            "osint_flags": osint_flags,
            "anomaly_interpretation": anomaly_result.get("interpretation"),
            "custom_regulatory_flags": custom_features
        },
        "engines_firing": [
            "Ensemble ML (XGBoost + RF + LR Binary Engine)",
            analysis_engine,
            "Isolation Forest (Metadata Anomaly)",
            "Python WHOIS (OSINT)",
            "Cryptographic AssetLinks Verifier",
            "RBI Key Fact Statement (KFS) Scanner",
            "Developer Fingerprinting Engine"
        ]
    }

    os.makedirs("threat_reports", exist_ok=True)
    try:
        with open(static_report_path, "w", encoding="utf-8") as f:
            json.dump(final_response, f, indent=4)
    except Exception as e:
        print(f"[!] Failed to save static report: {e}")

    return final_response


# -------------------------------------------------------------------
# ENDPOINTS
# -------------------------------------------------------------------

class DirectLinkPayload(BaseModel):
    download_url: str


@router.post("/analyze/unified")
async def analyze_unified_pipeline(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    if not file.filename.lower().endswith(".apk"):
        return {"error": f"Invalid file format: {file.filename}. Please upload a standard .apk binary."}

    temp_file_path = f"temp_{file.filename}"
    with open(temp_file_path, "wb") as buffer:
        buffer.write(await file.read())

    try:
        return _run_analysis_pipeline(temp_file_path, background_tasks)
    except Exception as e:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
        return {"error": str(e)}


@router.post("/analyze/unified/link")
async def analyze_unified_from_link(
    background_tasks: BackgroundTasks,
    payload: DirectLinkPayload
):
    temp_file_path = f"temp_{uuid.uuid4().hex}.apk"
    try:
        response = requests.get(payload.download_url, stream=True, timeout=15, verify=False)
        response.raise_for_status()
        with open(temp_file_path, "wb") as buffer:
            for chunk in response.iter_content(chunk_size=8192):
                buffer.write(chunk)
        return _run_analysis_pipeline(temp_file_path, background_tasks)
    except requests.exceptions.RequestException as e:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
        return {"error": f"Failed to download APK from link: {str(e)}"}
    except Exception as e:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
        return {"error": str(e)}


@router.get("/report/dynamic/{package_id}")
def get_dynamic_report(package_id: str):
    report_path = f"threat_reports/{package_id}_dynamic_report.json"

    if not os.path.exists(report_path):
        return {"error": "Report not found or sandbox detonation still in progress."}

    with open(report_path, "r", encoding="utf-8") as f:
        report_data = json.load(f)

    if "security_score" in report_data:
        report_data["sandbox_execution_score"] = report_data.pop("security_score")

    if "final_dynamic_verdict" in report_data:
        return report_data

    # Sandbox Evasion Check
    network_data = report_data.get("network_domains", [])
    trackers_info = report_data.get("trackers_found", {})
    tracker_count = trackers_info.get("detected_trackers", 0)

    if len(network_data) == 0 and tracker_count == 0:
        report_data["sandbox_heuristics"] = {
            "status": "EVASION_DETECTED",
            "interpretation": "App played dead. Zero network traffic or trackers detected."
        }
    else:
        report_data["sandbox_heuristics"] = {
            "status": "DETONATION_SUCCESSFUL",
            "interpretation": "App executed normally and revealed network behaviors."
        }

    # Malicious Network Intelligence
    # Malicious Network Intelligence — with classification
    flagged_domains = []
    for domain in network_data:
        d = domain.lower()
        
        # Skip unresolvable internal endpoints
        if d.endswith(('.s', '.local', '.internal')):
            continue
        
        classification = None
        
        if any(k in d for k in ["baidu", "sohu", "chinaz", "qq.com",
                                "xiaomi", "xmpush", "foxuc"]):
            classification = "CHINESE_INFRASTRUCTURE"
        elif d.endswith((".xyz", ".cc", ".su", ".top")):
            classification = "BURNER_DOMAIN"
        elif any(k in d for k in [".stg.", "-test.", "frontloan"]):
            classification = "STAGING_IN_PRODUCTION"
        
        if classification:
            flagged_domains.append({
                "domain": domain,
                "classification": classification,
                "risk": "HIGH"
            })

    report_data["financial_intelligence"] = {
        "extracted_upis": [],
        "flagged_burner_domains": flagged_domains
    }

    # Dynamic KFS Compliance Check
    strings_found = str(report_data.get("strings", [])).lower()
    activities = str(report_data.get("activities", [])).lower()
    combined_runtime = strings_found + " " + activities

    kfs_signals = {
        "apr_shown_at_runtime": any(x in combined_runtime for x in [
            "annual percentage rate", "apr", "interest rate", "% p.a", "per annum"
        ]),
        "kfs_screen_detected": any(x in combined_runtime for x in [
            "key fact", "kfs", "sanction letter", "loan summary", "loan agreement"
        ]),
        "grievance_shown": any(x in combined_runtime for x in [
            "grievance", "complaint", "nodal officer", "grievance redressal"
        ]),
        "cooling_off_mentioned": any(x in combined_runtime for x in [
            "cooling off", "cooling-off", "cancel loan", "loan cancellation"
        ]),
    }

    kfs_passed = sum(kfs_signals.values())
    report_data["dynamic_kfs_compliance"] = {
        "compliant": kfs_passed >= 2,
        "signals_found": kfs_passed,
        "signals_total": 4,
        "signals": kfs_signals,
        "verdict": (
            "KFS COMPLIANT AT RUNTIME — Required disclosures detected during execution"
            if kfs_passed >= 2
            else "KFS VIOLATION — Mandatory RBI disclosures absent at runtime"
        ),
        "rbi_mandate": "RBI Digital Lending Directions 2025 require KFS before loan execution"
    }

    if kfs_passed == 0 and \
       report_data.get("sandbox_heuristics", {}).get("status") == "DETONATION_SUCCESSFUL":
        report_data["dynamic_kfs_override"] = True

    # Final Verdict
    kfs_override = report_data.get("dynamic_kfs_override", False)
    if report_data["sandbox_heuristics"]["status"] == "EVASION_DETECTED" \
            or len(flagged_domains) > 0 \
            or kfs_override:
        reasons = []
        if report_data["sandbox_heuristics"]["status"] == "EVASION_DETECTED":
            reasons.append("sandbox evasion detected")
        if len(flagged_domains) > 0:
            reasons.append("malicious offshore network traffic")
        if kfs_override:
            reasons.append("zero KFS disclosures found at runtime — mandatory RBI requirement violated")
        report_data["final_dynamic_verdict"] = "CRITICAL"
        report_data["dynamic_override_reason"] = "CRITICAL: " + "; ".join(reasons).capitalize() + "."
    else:
        report_data["final_dynamic_verdict"] = "MAINTAIN_STATIC_SCORE"
        report_data["dynamic_override_reason"] = (
            "No new dynamic threats observed. Refer to initial static OSINT score."
        )

    try:
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)
    except Exception as e:
        print(f"[!] Failed to overwrite report file: {e}")

    return report_data


class PackageCheckPayload(BaseModel):
    package_id: str


@router.post("/analyze/check")
async def check_by_package_id(payload: PackageCheckPayload):
    """Citizen Portal — verify an app by package ID without uploading an APK."""
    package_id = payload.package_id.strip()

    if not package_id:
        return {"error": "Package ID is required"}

    static_path = f"threat_reports/{package_id}_static_report.json"
    if os.path.exists(static_path):
        with open(static_path, "r") as f:
            cached = json.load(f)
        return {
            "package_id": package_id,
            "found_on_playstore": bool(cached.get("playstore_name")),
            "app_name": cached.get("playstore_name"),
            "developer": cached.get("developer"),
            "verdict": cached.get("verdict"),
            "risk_score": cached.get("risk_breakdown", {}).get("final_composite_score", 0),
            "flagged_reasons": cached.get("threat_intelligence", {}).get("osint_flags", []),
            "in_dla_registry": cached.get("threat_intelligence", {}).get(
                "custom_regulatory_flags", {}).get("in_dla_registry", False),
            "message": "Cached result from previous full analysis.",
            "source": "cache"
        }

    scraped_data = fetch_app_metadata(package_id)

    if scraped_data.get("error") or not scraped_data.get("title"):
        return {
            "package_id": package_id,
            "found_on_playstore": False,
            "verdict": "HIGH",
            "risk_score": 0.9,
            "flagged_reasons": [
                "App not found on Play Store — possible Ghost App distributed via WhatsApp or Telegram"
            ],
            "in_dla_registry": False,
            "message": "This app is not on Play Store. Sideloaded APKs carry very high risk."
        }

    if is_known_legitimate_bank(scraped_data):
        return {
            "package_id": package_id,
            "found_on_playstore": True,
            "app_name": scraped_data.get("title"),
            "developer": scraped_data.get("developer"),
            "verdict": "LOW",
            "risk_score": 0.05,
            "flagged_reasons": [],
            "in_dla_registry": True,
            "message": f"{scraped_data.get('title')} is a verified legitimate bank application."
        }

    registry_result = lookup_nbfc(scraped_data.get("developer", ""))
    dla_result = lookup_dla_by_app_id(package_id)
    domain_result = {"domain_age_days": -1}
    features = extract_features(scraped_data, registry_result, domain_result)
    score_result = compute_risk_score(scraped_data, features)

    return {
        "package_id": package_id,
        "found_on_playstore": True,
        "app_name": scraped_data.get("title"),
        "developer": scraped_data.get("developer"),
        "installs": scraped_data.get("installs"),
        "rating": scraped_data.get("score"),
        "verdict": score_result["verdict"],
        "risk_score": score_result["risk_score"],
        "flagged_reasons": [r["signal"] for r in score_result.get("flagged_reasons", [])],
        "in_dla_registry": bool(dla_result.get("found")),
        "message": score_result.get("note", "")
    }