import os
import time
import requests
import json

ANALYZE_URL = "http://127.0.0.1:8000/api/v1/analyze/unified"
DYNAMIC_URL_BASE = "http://127.0.0.1:8000/api/v1/report/dynamic/"
SAMPLES_DIR = "cartel_samples"

def process_cartel():
    print("🚀 Starting AppGuard Cartel Batch Processor (With Timeouts)...")
    
    threat_network = {"nodes": [], "edges": []}
    apks = [f for f in os.listdir(SAMPLES_DIR) if f.endswith('.apk')]
    
    if not apks:
        print(f"❌ No APKs found in the '{SAMPLES_DIR}' directory.")
        return

    for apk_file in apks:
        file_path = os.path.join(SAMPLES_DIR, apk_file)
        print(f"\n[*] Submitting {apk_file} to Stage 1 (Static)...")
        
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (apk_file, f, 'application/vnd.android.package-archive')}
                response = requests.post(ANALYZE_URL, files=files)
        except Exception as e:
            print(f"    [!] Connection error uploading {apk_file}: {e}")
            continue
            
        if response.status_code != 200:
            print(f"    [!] Backend rejected {apk_file}: {response.text}")
            continue
            
        static_data = response.json()
        package_id = static_data.get("package_id")
        
        if not package_id:
            print(f"    [!] No package ID returned for {apk_file}. Skipping.")
            continue

        # Add the app as a central node
        if not any(n.get("id") == package_id for n in threat_network["nodes"]):
            threat_network["nodes"].append({"id": package_id, "type": "apk", "label": apk_file})
        
        print(f"    -> Stage 1 Complete. ID: {package_id}. Waiting for Sandbox...")

        # --- THE TIMEOUT UPGRADE ---
        dynamic_url = f"{DYNAMIC_URL_BASE}{package_id}"
        sandbox_finished = False
        max_attempts = 30 # 30 attempts * 15 seconds = 7.5 minutes max wait
        attempts = 0
        
        while not sandbox_finished and attempts < max_attempts:
            time.sleep(15) 
            attempts += 1
            
            try:
                dyn_response = requests.get(dynamic_url)
                
                if dyn_response.status_code == 200:
                    dyn_data = dyn_response.json()
                    if "final_dynamic_verdict" in dyn_data:
                        sandbox_finished = True
                        domains = dyn_data.get("network_domains", [])
                        print(f"    -> Stage 2 Complete! Found {len(domains)} domains in {attempts * 15}s.")
                        
                        for domain in domains:
                            if not any(n.get("id") == domain for n in threat_network["nodes"]):
                                threat_network["nodes"].append({"id": domain, "type": "domain", "label": domain})
                            threat_network["edges"].append({"source": package_id, "target": domain})
                else:
                    print(f"    ... polling ({attempts}/{max_attempts}) ...")
            except Exception as e:
                print(f"    [!] Error polling endpoint: {e}")
                
        if not sandbox_finished:
            print(f"    [!] TIMEOUT: Sandbox failed to return a verdict for {package_id} after 7.5 minutes. Moving on.")

    # Save the final graph data
    with open("cartel_graph_data.json", "w") as out:
        json.dump(threat_network, out, indent=4)
        
    print("\n✅ Batch Processing Complete! Data saved to 'cartel_graph_data.json'.")

if __name__ == "__main__":
    process_cartel()