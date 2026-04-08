import os
import requests
import json
from dotenv import load_dotenv

# Load credentials from your .env file
load_dotenv()

# Fallbacks match your exact Docker setup from the logs
MOBSF_URL = os.getenv("MOBSF_API_URL", "http://127.0.0.1:8001")
MOBSF_API_KEY = os.getenv("MOBSF_API_KEY", "c1ddfbebc15afa9ca60158c76046136a7f290ddc1bd5062bbe4a65e88b826187")

def detonate_in_sandbox(apk_filepath: str, package_id: str) -> dict:
    """
    Uploads the APK to the local MobSF Docker container for deep behavioral analysis.
    """
    if not os.path.exists(apk_filepath):
        print(f"[*] CRITICAL: Background task failed. APK not found at {apk_filepath}") # <-- ADD THIS
        return {"status": "error", "message": f"APK not found at {apk_filepath}"}

    if not os.path.exists(apk_filepath):
        return {"status": "error", "message": f"APK not found at {apk_filepath}"}

    headers = {"Authorization": MOBSF_API_KEY}

    try:
        # 1. Upload the APK to the Sandbox
        print(f"[*] Uploading {os.path.basename(apk_filepath)} to MobSF Sandbox at {MOBSF_URL}...")
        with open(apk_filepath, 'rb') as file_stream:
            files = {'file': (os.path.basename(apk_filepath), file_stream, 'application/octet-stream')}
            upload_response = requests.post(f"{MOBSF_URL}/api/v1/upload", headers=headers, files=files, timeout=30)
            
        upload_response.raise_for_status()
        scan_data = upload_response.json()
        file_hash = scan_data.get('hash')
        
        print(f"[*] Upload successful. File Hash: {file_hash}")

        # 2. Trigger the Automated Scan
        print("[*] Triggering automated dynamic analysis. This may take 30-60 seconds...")
        scan_payload = {'hash': file_hash}
        scan_response = requests.post(f"{MOBSF_URL}/api/v1/scan", headers=headers, data=scan_payload, timeout=600)
        scan_response.raise_for_status()
        
        report = scan_response.json()

        # 3. Extract the critical behavioral intelligence
        final_report = {
            "status": "success",
            "security_score": report.get("security_score", 100),
            "trackers_found": report.get("trackers", 0),
            "network_domains": list(report.get("domains", {}).keys())[:5],
            "permissions_analyzed": len(report.get("permissions", {})),
            "malware_behavior": report.get("malware_behavior", [])
        }

        os.makedirs("threat_reports", exist_ok=True)
        # We now use the package_id to save the file so the API can find it later
        report_path = f"threat_reports/{package_id}_dynamic_report.json"
        
        with open(report_path, "w") as f:
            json.dump(final_report, f, indent=4)
            
        print(f"[*] SUCCESS: Dynamic Sandbox Report saved to {report_path}")
        
        # --- THIS ANSWERS YOUR FIRST QUESTION ---
        print("\n--- LIVE TERMINAL REPORT ---")
        print(json.dumps(final_report, indent=2))
        
        return final_report

    except requests.exceptions.RequestException as e:
        print(f"[*] Sandbox network error: {str(e)}")
        return {"status": "error", "message": f"Sandbox network error: {str(e)}"}
    except Exception as e:
        print(f"[*] Sandbox execution failed: {str(e)}")
        return {"status": "error", "message": f"Sandbox execution failed: {str(e)}"}
        
    finally:
        # 4. ALWAYS clean up: Destroy the malware file after analysis or failure
        if os.path.exists(apk_filepath):
            try:
                os.remove(apk_filepath)
                print(f"[*] Cleaned up temporary file: {os.path.basename(apk_filepath)}")
            except Exception as cleanup_error:
                print(f"[*] Could not delete temporary file: {cleanup_error}")

if __name__ == "__main__":
    # Testing block
    test_apk_path = '/home/Hp/rbi-track2/aufinance.apk'
    
    print("--- Initiating MobSF Sandbox Test ---")
    result = detonate_in_sandbox(test_apk_path)
    
    print("\n--- Sandbox Detonation Report ---")
    print(json.dumps(result, indent=2))