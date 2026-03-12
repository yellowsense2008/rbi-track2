from google_play_scraper import app as gplay_app
import whois
from datetime import datetime

def fetch_app_metadata(app_id: str) -> dict:
    try:
        result = gplay_app(app_id, lang='en', country='in')
        return {
            "app_id": app_id,
            "title": result.get("title"),
            "developer": result.get("developer"),
            "developer_email": result.get("developerEmail"),
            "developer_website": result.get("developerWebsite"),
            "installs": result.get("realInstalls", 0),
            "score": result.get("score", 0),
            "ratings": result.get("ratings", 0),
            "reviews": result.get("reviews", 0),
            "description": result.get("description", ""),
            "permissions": result.get("permissions", []),
            "genre": result.get("genre"),
            "released": str(result.get("released", "")),
            "updated": str(result.get("updated", "")),
            "error": None
        }
    except Exception as e:
        return {
            "app_id": app_id, "error": str(e), "title": None,
            "developer": None, "developer_email": None,
            "developer_website": None, "installs": 0, "score": 0,
            "ratings": 0, "reviews": 0, "description": "",
            "permissions": [], "genre": None,
            "released": None, "updated": None
        }

def analyze_domain(url: str) -> dict:
    if not url:
        return {"domain": None, "domain_age_days": -1, "registrar": None}
    try:
        domain = url.replace("https://","").replace("http://","").split("/")[0]
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        age_days = (datetime.now() - created).days if created else -1
        return {
            "domain": domain,
            "domain_age_days": age_days,
            "registrar": str(w.registrar)
        }
    except Exception as e:
        return {"domain": None, "domain_age_days": -1, "registrar": None}