import requests
from bs4 import BeautifulSoup
import re

def scan_for_kfs_osint(app_description: str, developer_website: str) -> dict:
    """
    Scans the app's public footprint (Play Store description and official website) 
    for RBI-mandated Key Fact Statement and lending terminology.
    """
    # We expanded this to include the specific mandates from the Oct 1, 2024 RBI guidelines
    mandated_terms = [
        "apr", "annual percentage rate", "nbfc", "interest rate", 
        "repayment", "processing fee", "cibil", "partner bank"
    ]
    found_terms = set()
    
    # 1. First, check the Play Store Description (Fastest)
    desc_lower = str(app_description).lower()
    for term in mandated_terms:
        if term in desc_lower:
            found_terms.add(term)
            
    # 2. If the description is vague, aggressively scan their website's homepage
    if len(found_terms) < 3 and developer_website and developer_website.startswith("http"):
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            response = requests.get(developer_website, headers=headers, timeout=4)
            if response.status_code == 200:
                # Rip all the visible text off their website
                soup = BeautifulSoup(response.text, "html.parser")
                website_text = soup.get_text().lower()
                
                for term in mandated_terms:
                    if term in website_text:
                        found_terms.add(term)
        except Exception:
            pass # If the website is dead, we just rely on what we found in the description

    # 3. The Verdict
    # If we can't find at least 2 basic financial terms across their app description AND website, 
    # it is a massive transparency violation.
    if len(found_terms) < 2:
        return {
            "compliant": False, 
            "flag": "REGULATORY VIOLATION: App description and website lack transparent lending terms (APR, NBFC status, Interest Rates). High probability of predatory lending."
        }
        
    return {"compliant": True, "flag": None}