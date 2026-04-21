import os
import time
import requests
import json

ANALYZE_URL = "http://127.0.0.1:8000/api/v1/analyze/unified"
DYNAMIC_URL_BASE = "http://127.0.0.1:8000/api/v1/report/dynamic/"
SAMPLES_DIR = "cartel_samples"

# Known legitimate infrastructure domains — filter these out of the cartel graph
# These appear in almost every Android app and add noise, not signal
BENIGN_INFRASTRUCTURE = {
    "www.openssl.org", "www.apple.com", "pagead2.googlesyndication.com",
    "plus.google.com", "crbug.com", "github.com", "flutter.dev",
    "api.flutter.dev", "issuetracker.google.com", "fonts.gstatic.com",
    "www.google.com", "google.com", "googleapis.com", "gstatic.com",
    "firebase.google.com", "firebaseio.com", "crashlytics.com",
    "purl.org", "xerces.apache.org", "xmlpull.org", "schema.org",
    "facebook.com", "graph.facebook.com", "connect.facebook.net",
    "twitter.com", "api.twitter.com", "amazon.com", "amazonaws.com",
    "s3.amazonaws.com", "cloudfront.net", "akamai.com", "akamaiedge.net",
    "microsoft.com", "live.com", "outlook.com",
    "adjust.com", "adjust.io", "adjust.net.in", "adjust.world",
    "app.adjust.com", "app.adjust.world", "ssrv.adjust.com",
    "gdpr.adjust.io", "gdpr.adjust.world", "gdpr.us.adjust.com",
    "api.mixpanel.com", "cdn.branch.io", "api.branch.io",
    "swasrec2.npci.org.in",  # legitimate NPCI UPI infrastructure
    "monnai.com",             # legitimate Indian fintech credit check
    "s3.ap-south-1.amazonaws.com",  # legitimate AWS India region
    "apac-faceid.hyperverge.co",    # legitimate KYC provider
    "acs.icicibank.com",     # legitimate ICICI bank
    "www.kotak.com",         # legitimate Kotak bank
    "api.whatsapp.com",      # legitimate WhatsApp
    "cipa.jp",               # legitimate certificate authority
    "defaultlink.com",       # legitimate deep link service
    "flutter.dev",
}

def is_suspicious_domain(domain: str) -> bool:
    d = domain.lower().strip()

    # Skip unresolvable internal SDK endpoints
    if d.endswith(('.s', '.local', '.internal', '.sdk', '.test')):
        return False

    # Skip known legitimate infrastructure
    if d in BENIGN_INFRASTRUCTURE:
        return False

    # Skip subdomains of known legitimate services
    benign_suffixes = [
        'google.com', 'googleapis.com', 'gstatic.com', 'firebase.com',
        'amazonaws.com', 'cloudfront.net', 'akamaiedge.net',
        'facebook.com', 'fbcdn.net', 'adjust.com', 'adjust.io',
        'adjust.world', 'npci.org.in', 'icicibank.com', 'kotak.com',
    ]
    for suffix in benign_suffixes:
        if d.endswith('.' + suffix) or d == suffix:
            return False

    # HIGH SIGNAL — Burner TLDs (scammer favorite)
    if d.endswith((".xyz", ".cc", ".su", ".top", ".pw", ".tk", ".ml")):
        return True

    # HIGH SIGNAL — Chinese state infrastructure
    # These are not just Chinese companies — they are state-linked
    # data collection infrastructure with no legitimate reason to
    # appear in an Indian lending app
    chinese_state_infra = [
        "baidu.com", "map.baidu.com",     # Chinese state search/maps
        "sohu.com",                         # Chinese state media
        "chinaz.com",                       # Chinese IP lookup tool
        "qq.com", "weixin.qq.com",         # Tencent state-linked
        "xiaomi.com", "miui.com",          # Xiaomi state-linked
        "xmpush", "xmpush",                # Xiaomi push service
        "foxuc.net",                        # Known fraud CDN
        "gogosky.in",                       # Known fraud backend
    ]
    if any(k in d for k in chinese_state_infra):
        return True

    # MEDIUM SIGNAL — Staging/test APIs in production (compliance violation)
    if any(k in d for k in [".stg.", "-test.", "-staging.", "test-api"]):
        return True

    # MEDIUM SIGNAL — Known fraud app backends
    if any(k in d for k in ["frontloan", "creditt", "loaneasy"]):
        return True

    return False

def process_cartel():
    print("Starting AppGuard Cartel Batch Processor...")

    threat_network = {"nodes": [], "edges": []}
    apks = [f for f in os.listdir(SAMPLES_DIR) if f.endswith('.apk')]

    if not apks:
        print(f"No APKs found in '{SAMPLES_DIR}'.")
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

        verdict = static_data.get("verdict", "UNKNOWN")
        print(f"    -> Static verdict: {verdict} | ID: {package_id}")

        # Add app node with verdict info
        if not any(n.get("id") == package_id for n in threat_network["nodes"]):
            threat_network["nodes"].append({
                "id": package_id,
                "type": "apk",
                "label": apk_file,
                "verdict": verdict,
                "risk_score": static_data.get("risk_breakdown", {}).get("final_composite_score", 0)
            })

        print(f"    -> Waiting for sandbox...")

        dynamic_url = f"{DYNAMIC_URL_BASE}{package_id}"
        sandbox_finished = False
        max_attempts = 30
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

                        # Only add SUSPICIOUS domains to the graph
                        suspicious_count = 0
                        for domain in domains:
                            if is_suspicious_domain(domain):
                                suspicious_count += 1

                                # Classify for frontend color-coding
                                d_lower = domain.lower()
                                chinese_state_infra = [
                                    "baidu.com", "sohu.com", "chinaz.com", "qq.com",
                                    "xiaomi.com", "miui.com", "xmpush", "foxuc.net"
                                ]
                                if any(k in d_lower for k in chinese_state_infra):
                                    classification = "CHINESE_INFRASTRUCTURE"
                                elif d_lower.endswith((".xyz", ".cc", ".su", ".top")):
                                    classification = "BURNER_DOMAIN"
                                elif any(k in d_lower for k in [".stg.", "-test.", "test-api"]):
                                    classification = "STAGING_IN_PRODUCTION"
                                else:
                                    classification = "SUSPICIOUS"

                                if not any(n.get("id") == domain for n in threat_network["nodes"]):
                                    threat_network["nodes"].append({
                                        "id": domain,
                                        "type": "domain",
                                        "label": domain,
                                        "classification": classification
                                    })
                                threat_network["edges"].append({
                                    "source": package_id,
                                    "target": domain
                                })

                        print(f"    -> Sandbox complete! {suspicious_count} suspicious domains in {attempts * 15}s.")
                else:
                    print(f"    ... polling ({attempts}/{max_attempts}) ...")
            except Exception as e:
                print(f"    [!] Error polling: {e}")

        if not sandbox_finished:
            print(f"    [!] TIMEOUT: Sandbox failed for {package_id}. Moving on.")

    with open("cartel_graph_data.json", "w") as out:
        json.dump(threat_network, out, indent=4)

    apk_count = len([n for n in threat_network["nodes"] if n["type"] == "apk"])
    domain_count = len([n for n in threat_network["nodes"] if n["type"] == "domain"])
    print(f"\nBatch Complete! {apk_count} apps | {domain_count} suspicious domains | {len(threat_network['edges'])} connections")
    print("Data saved to cartel_graph_data.json")


if __name__ == "__main__":
    process_cartel()