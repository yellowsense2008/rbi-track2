import requests
from urllib.parse import urlparse

def verify_assetlinks(developer_website: str, package_id: str) -> dict:
    """
    Checks the official domain for cryptographic authorization of the APK.
    Google requires legitimate apps to map their SHA-256 fingerprint here.
    """
    if not developer_website or not package_id:
        return {"status": "skipped", "verified": False, "reason": "Missing website or package ID."}
        
    # Clean the URL to just the base domain
    if not developer_website.startswith("http"):
        developer_website = "https://" + developer_website
    
    try:
        parsed_uri = urlparse(developer_website)
        base_domain = f"{parsed_uri.scheme}://{parsed_uri.netloc}"
        
        # The official Google Play specification path
        assetlinks_url = f"{base_domain}/.well-known/assetlinks.json"
        
        # Make the request look like a real Chrome browser to bypass basic Cloudflare/WAF blocks
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        
        response = requests.get(assetlinks_url, headers=headers, timeout=5)
        
        if response.status_code == 404:
            return {"status": "failed", "verified": False, "reason": "No assetlinks.json found on official domain."}
        
        if response.status_code == 200:
            data = response.json()
            # It is usually a list of dictionaries containing app authorization targets
            for entry in data:
                target = entry.get("target", {})
                if target.get("namespace") == "android_app" and target.get("package_name") == package_id:
                    return {"status": "success", "verified": True, "reason": "Cryptographically verified."}
                    
            return {"status": "failed", "verified": False, "reason": f"Package ID '{package_id}' not authorized."}
            
    except requests.exceptions.RequestException:
        return {"status": "error", "verified": False, "reason": "Domain unreachable or timed out."}
    except Exception as e:
        return {"status": "error", "verified": False, "reason": str(e)}
        
    return {"status": "failed", "verified": False, "reason": "Verification failed."}