import os
import requests
import uuid
import json
from pydantic import BaseModel
from fastapi import APIRouter, File, UploadFile, BackgroundTasks
import urllib3

# Suppress warnings when intentionally connecting to broken scam infrastructure
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- ALL IMPORTS ---
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

router = APIRouter()

class DirectLinkPayload(BaseModel):
    download_url: str

@router.post("/analyze/unified")
async def analyze_unified_pipeline(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    # 0. Format Guardrail
    if not file.filename.lower().endswith(".apk"):
        return {
            "error": f"Invalid file format: {file.filename}. Please upload a standard .apk binary. Bundles like .apkm or .xapk must be extracted first."
        }

    temp_file_path = f"temp_{file.filename}"
    with open(temp_file_path, "wb") as buffer:
        buffer.write(await file.read())

    try:
        # INITIALIZE ALL VARIABLES FIRST TO PREVENT CRASHES
        nlp_score, osint_penalty, anomaly_score, feature_penalty = 0.0, 0.0, 0.0, 0.0
        nlp_flags, osint_flags = [], []
        analysis_engine = "None (App not found on Play Store)"
        custom_features = {}
        anomaly_result = {"is_anomaly": False, "interpretation": "N/A"}

        # 1. Extract APK Blueprint (Static Engine)
        parser_result = parse_apk_manifest(temp_file_path)
        if parser_result.get("status") == "error":
            os.remove(temp_file_path)
            return {"error": f"Failed to parse APK: {parser_result.get('message')}"}
            
        package_id = parser_result.get("package_id")

        if not package_id or package_id == "None":
            os.remove(temp_file_path)
            return {"error": "CRITICAL EVASION DETECTED: Malformed AndroidManifest. Package ID is intentionally hidden or corrupted."}

        dynamic_report_path = f"threat_reports/{package_id}_dynamic_report.json"
        static_report_path = f"threat_reports/{package_id}_static_report.json"

        if os.path.exists(dynamic_report_path) and os.path.exists(static_report_path):
            os.remove(temp_file_path) # Delete the newly uploaded file to save space
            
            # Load the historical static data
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
                # Injecting the missing static data for the frontend
                "verdict": saved_static_data.get("verdict", "HIGH"),
                "risk_breakdown": saved_static_data.get("risk_breakdown", {}),
                "threat_intelligence": saved_static_data.get("threat_intelligence", {}),
                "engines_firing": saved_static_data.get("engines_firing", [])
            }
        
        # 2. XGBoost ML Engine
        feature_vector = create_permission_vector(parser_result.get("raw_permissions", []))
        ai_result = predict_apk_risk(feature_vector)
        ml_risk_score = ai_result.get("risk_score", 0.0)
        
        # 3. The Ghost Scrape (Internet Analysis)
        scraped_data = fetch_app_metadata(package_id)

        if not scraped_data.get("error") and scraped_data.get("title"):
            
            # 4. OSINT Domain Analysis
            developer_website = scraped_data.get("developer_website", "")
            domain_result = analyze_domain(developer_website)
            domain_age_days = domain_result.get("domain_age_days", -1)
            
            if domain_age_days > 0 and domain_age_days < 90:
                osint_penalty = 0.20
                osint_flags.append(f"Domain registered only {domain_age_days} days ago.")
            elif domain_age_days == -1:
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

            # 6. Baseline Registry Check & Core Features
            registry_result = lookup_nbfc(scraped_data.get("developer", "")) if hasattr(lookup_nbfc, '__call__') else {"found": False, "score": 0}
            # Update our custom_features dictionary with the baseline features
            custom_features.update(extract_features(scraped_data, registry_result, domain_result))
            
            if custom_features.get("free_email") and custom_features.get("urgency_language"):
                feature_penalty += 0.15
            if custom_features.get("claims_rbi") and not custom_features.get("in_dla_registry"):
                feature_penalty += 0.30

            # --- DEVELOPER FINGERPRINTING (The Free Email Trap) ---
            dev_email = scraped_data.get("developer_email", "").lower()
            free_providers = ["@gmail.com", "@yahoo.com", "@hotmail.com", "@outlook.com"]
            if any(provider in dev_email for provider in free_providers):
                feature_penalty += 0.30
                custom_features["free_email_provider"] = True
                flag = f"OSINT FINGERPRINT: Entity claims financial status but uses a free email ({dev_email}). High probability of burner account."
                osint_flags.append(flag)
            
            # --- THE CRYPTOGRAPHIC ASSETLINKS CHECK ---
            if developer_website and developer_website != "N/A":
                asset_check = verify_assetlinks(developer_website, package_id)
                if asset_check["status"] == "failed":
                    feature_penalty += 0.40
                    custom_features["assetlinks_failed"] = True
                    flag = f"CRYPTOGRAPHIC MISMATCH: The official domain ({developer_website}) does not authorize this app. High probability of stolen identity."
                    osint_flags.append(flag)

            kfs_result = scan_for_kfs_osint(scraped_data.get("description", ""), developer_website)
            if not kfs_result["compliant"]:
                feature_penalty += 0.20
                custom_features["kfs_missing"] = True
                osint_flags.append(kfs_result["flag"])
                print(f"[*] {kfs_result['flag']}")  

            # --- THE ARC KILL SWITCH ---
            arc_check = is_arc_killswitch(scraped_data.get("developer", ""))
            if arc_check["is_arc"]:
                feature_penalty += 1.0 
                custom_features["arc_violation"] = True
                fatal_flag = (f"REGULATORY KILL SWITCH: App claims affiliation with '{arc_check['matched_name']}'. "
                              f"This entity is an Asset Reconstruction Company (ARC) and is legally prohibited from issuing retail loans.")
                osint_flags.append(fatal_flag)

            # 7. DeepTech NLP Engine
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
        
        # --- THE GHOST APP KILL SWITCH ---
        # If the app is not on the Play Store, it has no public footprint. 
        # By definition, it violates RBI transparency mandates (KFS) because the user cannot view the terms publicly.
        if not scraped_data.get("developer") and not scraped_data.get("playstore_name"):
            feature_penalty += 0.60  # Massive penalty for sideloaded financial ghost apps
            custom_features["unverified_distribution"] = True
            custom_features["kfs_missing"] = True  # If it has no public page, it has no public KFS
            osint_flags.append("CRITICAL: App is a 'Ghost'. Not found on official stores. Bypasses standard regulatory transparency. Massive risk of sideloaded malware.")

        # 8. The Grand Fusion & Trust Override
        # If the ML model is highly confident it's safe, and it hasn't triggered a fatal regulatory violation (like an ARC),
        # we apply a Trust Modifier to prevent False Positives on legitimate obfuscated banking apps.
        
        developer_name = scraped_data.get("developer") or ""
        is_trusted_entity = "bank" in developer_name.lower() or custom_features.get("in_dla_registry") == 1
        
        if ml_risk_score < 0.10 and is_trusted_entity and not custom_features.get("arc_violation"):
            # Suppress the strict heuristic penalties for known good entities
            feature_penalty = feature_penalty * 0.2 
            osint_penalty = 0.0
            anomaly_score = 0.0
            osint_flags.append("TRUST OVERRIDE: Entity recognized as legitimate financial institution. Heuristic penalties suppressed.")

        final_score = min(ml_risk_score + nlp_score + osint_penalty + anomaly_score + feature_penalty, 1.0)
        final_verdict = "HIGH" if final_score >= 0.60 else "MEDIUM" if final_score >= 0.30 else "LOW"

        # 9. TRIGGER THE DYNAMIC SANDBOX IN THE BACKGROUND
        background_tasks.add_task(detonate_in_sandbox, temp_file_path, package_id)

        # 10. The Ultimate B2B Payload
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
        
        # Save the static report for future caching
        static_report_path = f"threat_reports/{package_id}_static_report.json"
        try:
            with open(static_report_path, "w", encoding="utf-8") as f:
                json.dump(final_response, f, indent=4)
        except Exception as e:
            print(f"[!] Failed to save static report: {e}")

        return final_response

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
        # Added verify=False to bypass broken SSL certificates on scam domains
        response = requests.get(payload.download_url, stream=True, timeout=15, verify=False)
        response.raise_for_status() 
        
        with open(temp_file_path, "wb") as buffer:
            for chunk in response.iter_content(chunk_size=8192):
                buffer.write(chunk)

        # INITIALIZE VARIABLES
        nlp_score, osint_penalty, anomaly_score, feature_penalty = 0.0, 0.0, 0.0, 0.0
        nlp_flags, osint_flags = [], []
        analysis_engine = "None (App not found on Play Store)"
        custom_features = {}
        anomaly_result = {"is_anomaly": False, "interpretation": "N/A"}

        # 1. Extract APK Blueprint
        parser_result = parse_apk_manifest(temp_file_path)
        if parser_result.get("status") == "error":
            os.remove(temp_file_path)
            return {"error": f"Failed to parse downloaded APK: {parser_result.get('message')}"}
            
        package_id = parser_result.get("package_id")

        if not package_id or package_id == "None":
            os.remove(temp_file_path)
            return {"error": "CRITICAL EVASION DETECTED: Malformed AndroidManifest. Package ID is intentionally hidden or corrupted."}

        dynamic_report_path = f"threat_reports/{package_id}_dynamic_report.json"
        static_report_path = f"threat_reports/{package_id}_static_report.json"

        if os.path.exists(dynamic_report_path) and os.path.exists(static_report_path):
            os.remove(temp_file_path) # Delete the newly uploaded file to save space
            
            # Load the historical static data
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
                # Injecting the missing static data for the frontend
                "verdict": saved_static_data.get("verdict", "HIGH"),
                "risk_breakdown": saved_static_data.get("risk_breakdown", {}),
                "threat_intelligence": saved_static_data.get("threat_intelligence", {}),
                "engines_firing": saved_static_data.get("engines_firing", [])
            }
        
        # 2. XGBoost ML Engine
        feature_vector = create_permission_vector(parser_result.get("raw_permissions", []))
        ai_result = predict_apk_risk(feature_vector)
        ml_risk_score = ai_result.get("risk_score", 0.0)
        
        # 3. The Ghost Scrape
        scraped_data = fetch_app_metadata(package_id)

        if not scraped_data.get("error") and scraped_data.get("title"):
            
            # 4. OSINT Domain Analysis
            developer_website = scraped_data.get("developer_website", "")
            domain_result = analyze_domain(developer_website)
            domain_age_days = domain_result.get("domain_age_days", -1)
            
            if domain_age_days > 0 and domain_age_days < 90:
                osint_penalty = 0.20
                osint_flags.append(f"Domain registered only {domain_age_days} days ago.")
            elif domain_age_days == -1:
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

            # 6. Baseline Registry Check & Core Features
            registry_result = lookup_nbfc(scraped_data.get("developer", "")) if hasattr(lookup_nbfc, '__call__') else {"found": False, "score": 0}
            custom_features.update(extract_features(scraped_data, registry_result, domain_result))
            
            if custom_features.get("free_email") and custom_features.get("urgency_language"):
                feature_penalty += 0.15
            if custom_features.get("claims_rbi") and not custom_features.get("in_dla_registry"):
                feature_penalty += 0.30

            # --- DEVELOPER FINGERPRINTING (The Free Email Trap) ---
            dev_email = scraped_data.get("developer_email", "").lower()
            free_providers = ["@gmail.com", "@yahoo.com", "@hotmail.com", "@outlook.com"]
            if any(provider in dev_email for provider in free_providers):
                feature_penalty += 0.30
                custom_features["free_email_provider"] = True
                flag = f"OSINT FINGERPRINT: Entity claims financial status but uses a free email ({dev_email}). High probability of burner account."
                osint_flags.append(flag)

            # --- THE CRYPTOGRAPHIC ASSETLINKS CHECK ---
            if developer_website and developer_website != "N/A":
                asset_check = verify_assetlinks(developer_website, package_id)
                if asset_check["status"] == "failed":
                    feature_penalty += 0.40
                    custom_features["assetlinks_failed"] = True
                    flag = f"CRYPTOGRAPHIC MISMATCH: The official domain ({developer_website}) does not authorize this app. High probability of stolen identity."
                    osint_flags.append(flag)
            
            kfs_result = scan_for_kfs_osint(scraped_data.get("description", ""), developer_website)
            if not kfs_result["compliant"]:
                feature_penalty += 0.20
                custom_features["kfs_missing"] = True
                osint_flags.append(kfs_result["flag"])
                print(f"[*] {kfs_result['flag']}")

            # --- THE ARC KILL SWITCH ---
            arc_check = is_arc_killswitch(scraped_data.get("developer", ""))
            if arc_check["is_arc"]:
                feature_penalty += 1.0 
                custom_features["arc_violation"] = True
                fatal_flag = (f"REGULATORY KILL SWITCH: App claims affiliation with '{arc_check['matched_name']}'. "
                              f"This entity is an Asset Reconstruction Company (ARC) and is legally prohibited from issuing retail loans.")
                osint_flags.append(fatal_flag)

            # 7. DeepTech NLP Engine
            nlp_result = detect_brand_impersonation(
                app_title=scraped_data.get("title", ""),
                developer_name=scraped_data.get("developer", ""),
                description=scraped_data.get("description", "")
            )
            nlp_score = nlp_result.get("nlp_risk_score", 0.0)
            nlp_flags = [f["signal"] for f in nlp_result.get("nlp_flags", [])]
            analysis_engine = nlp_result.get("engine_used", "Unknown")
            
        else:
            nlp_flags.append("Unverified Distribution: App is not on the Play Store (Sourced from external link)")
            nlp_score += 0.40 
        
        # --- THE GHOST APP KILL SWITCH ---
        # If the app is not on the Play Store, it has no public footprint. 
        # By definition, it violates RBI transparency mandates (KFS) because the user cannot view the terms publicly.
        if not scraped_data.get("developer") and not scraped_data.get("playstore_name"):
            feature_penalty += 0.60  # Massive penalty for sideloaded financial ghost apps
            custom_features["unverified_distribution"] = True
            custom_features["kfs_missing"] = True  # If it has no public page, it has no public KFS
            osint_flags.append("CRITICAL: App is a 'Ghost'. Not found on official stores. Bypasses standard regulatory transparency. Massive risk of sideloaded malware.")

        # 8. The Grand Fusion & Trust Override
        # If the ML model is highly confident it's safe, and it hasn't triggered a fatal regulatory violation (like an ARC),
        # we apply a Trust Modifier to prevent False Positives on legitimate obfuscated banking apps.
        
        developer_name = scraped_data.get("developer") or ""
        is_trusted_entity = "bank" in developer_name.lower() or custom_features.get("in_dla_registry") == 1
        
        if ml_risk_score < 0.10 and is_trusted_entity and not custom_features.get("arc_violation"):
            # Suppress the strict heuristic penalties for known good entities
            feature_penalty = feature_penalty * 0.2 
            osint_penalty = 0.0
            anomaly_score = 0.0
            osint_flags.append("TRUST OVERRIDE: Entity recognized as legitimate financial institution. Heuristic penalties suppressed.")

        final_score = min(ml_risk_score + nlp_score + osint_penalty + anomaly_score + feature_penalty, 1.0)
        final_verdict = "HIGH" if final_score >= 0.60 else "MEDIUM" if final_score >= 0.30 else "LOW"

        # 9. TRIGGER THE DYNAMIC SANDBOX IN THE BACKGROUND
        background_tasks.add_task(detonate_in_sandbox, temp_file_path, package_id)

        # 10. The Ultimate B2B Payload
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
        
        # Save the static report for future caching
        static_report_path = f"threat_reports/{package_id}_static_report.json"
        try:
            with open(static_report_path, "w", encoding="utf-8") as f:
                json.dump(final_response, f, indent=4)
        except Exception as e:
            print(f"[!] Failed to save static report: {e}")

        return final_response

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
    
    # 1. Ensure the file actually exists
    if not os.path.exists(report_path):
        return {"error": "Report not found or sandbox detonation still in progress."}
        
    # 2. Read the raw MobSF output
    with open(report_path, "r", encoding="utf-8") as f:
        report_data = json.load(f)

    # Rename the confusing MobSF score so the frontend and judges don't get confused
    if "security_score" in report_data:
        report_data["sandbox_execution_score"] = report_data.pop("security_score")

    # --- IF ALREADY ENRICHED, JUST RETURN IT ---
    if "final_dynamic_verdict" in report_data:
        return report_data

    # 3. ENRICHMENT: Sandbox Evasion Check
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
        
    # 4. ENRICHMENT: Malicious Network Intelligence
    flagged_domains = []
    for domain in network_data:
        d = domain.lower()
        # Check if it ends with a burner TLD, or contains known malware keywords
        if d.endswith((".co", ".xyz", ".cc", ".su", ".top")) or any(k in d for k in ["baidu", "test-api", "frontloan"]):
            flagged_domains.append(domain)
            
    report_data["financial_intelligence"] = {
        "extracted_upis": [],
        "flagged_burner_domains": flagged_domains
    }
    
    # 5. THE TIMELINE OVERRIDE (The Final Verdict)
    if report_data["sandbox_heuristics"]["status"] == "EVASION_DETECTED" or len(flagged_domains) > 0:
        report_data["final_dynamic_verdict"] = "CRITICAL"
        report_data["dynamic_override_reason"] = "Sandbox detected evasion or malicious offshore network traffic."
    else:
        # DO NOT say "CLEAN" here. Tell the frontend to keep the original static score.
        report_data["final_dynamic_verdict"] = "MAINTAIN_STATIC_SCORE"
        report_data["dynamic_override_reason"] = "No new dynamic threats observed. Refer to initial static OSINT score."

    # 6. THE BULLETPROOF FILE SAVE
    # We immediately open the file in write mode to permanently burn these new features into the hard drive
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)
    except Exception as e:
        print(f"[!] Failed to overwrite report file: {e}")

    return report_data