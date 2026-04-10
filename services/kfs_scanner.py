import requests
import re
from bs4 import BeautifulSoup

def _load_nbfc_names():
    try:
        import pandas as pd
        import os
        csv_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'nbfc_list.csv')
        df = pd.read_csv(csv_path)
        return df['company_name'].str.lower().tolist()
    except Exception:
        return []

KNOWN_NBFC_NAMES = _load_nbfc_names()

def _check_grievance_officer(text: str) -> bool:
    patterns = [
        r'grievance\s+(redressal\s+)?officer',
        r'nodal\s+officer',
        r'complaint\s+officer',
    ]
    text_lower = text.lower()
    for pattern in patterns:
        if re.search(pattern, text_lower):
            return True
    return False

def _check_nbfc_partner_named(text: str) -> bool:
    text_lower = text.lower()
    for nbfc in KNOWN_NBFC_NAMES:
        if len(nbfc) > 6 and nbfc in text_lower:
            return True
    cin_pattern = r'[UL]\d{5}[A-Z]{2}\d{4}[A-Z]{3}\d{6}'
    if re.search(cin_pattern, text):
        return True
    return False

def _check_privacy_policy(text: str, soup=None) -> bool:
    if re.search(r'https?://[^\s]+privac[^\s]*', text.lower()):
        return True
    if soup:
        for link in soup.find_all('a', href=True):
            href = link.get('href', '').lower()
            link_text = link.get_text().lower()
            if 'privacy' in href or 'privacy' in link_text:
                return True
    return False

def _check_physical_address(text: str) -> bool:
    if re.search(r'\b\d{6}\b', text):
        keywords = [
            'floor', 'building', 'road', 'street', 'nagar',
            'colony', 'sector', 'phase', 'plot', 'tower',
            'office', 'mumbai', 'delhi', 'bengaluru', 'bangalore',
            'hyderabad', 'chennai', 'pune', 'ahmedabad'
        ]
        text_lower = text.lower()
        for kw in keywords:
            if kw in text_lower:
                return True
    return False

def _check_apr_disclosed(text: str) -> bool:
    text_lower = text.lower()
    if 'annual percentage rate' in text_lower or ' apr ' in text_lower:
        return True
    if re.search(r'\d+(\.\d+)?%\s*(p\.a\.|per\s+annum|annually)', text_lower):
        return True
    return False

def scan_for_kfs_osint(app_description: str, developer_website: str) -> dict:
    """
    Verifies public-facing RBI Digital Lending Directions 2025 compliance.
    Checks what MUST be publicly visible per RBI mandate.
    Full KFS document verification requires sandbox analysis.
    """
    full_text = str(app_description or "")
    soup = None
    website_reachable = False

    if developer_website and developer_website.startswith("http"):
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            response = requests.get(developer_website, headers=headers, timeout=5)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                full_text += " " + soup.get_text()
                website_reachable = True
        except Exception:
            pass

    signals = {
        "grievance_officer_named": _check_grievance_officer(full_text),
        "nbfc_partner_named": _check_nbfc_partner_named(full_text),
        "privacy_policy_url": _check_privacy_policy(full_text, soup),
        "physical_address_present": _check_physical_address(full_text),
        "apr_disclosed": _check_apr_disclosed(full_text),
        "website_reachable": website_reachable,
    }

    passed = sum(1 for v in signals.values() if v)
    violations = []

    if not signals["grievance_officer_named"]:
        violations.append(
            "No Grievance Redressal Officer — "
            "mandatory under RBI Digital Lending Directions 2025"
        )
    if not signals["nbfc_partner_named"]:
        violations.append(
            "No specific NBFC/Bank partner named — "
            "fake apps claim 'RBI registered' without naming the entity"
        )
    if not signals["privacy_policy_url"]:
        violations.append(
            "No Privacy Policy URL — "
            "mandatory under RBI guidelines and DPDP Act 2023"
        )
    if not signals["physical_address_present"]:
        violations.append(
            "No registered physical address — "
            "legitimate NBFCs must disclose registered office"
        )
    if not signals["apr_disclosed"]:
        violations.append(
            "APR not disclosed publicly — "
            "RBI mandates upfront APR disclosure before loan offer"
        )
    if not signals["website_reachable"]:
        violations.append(
            "Developer website unreachable — "
            "predatory apps often have dead or fake websites"
        )

    compliant = passed >= 4

    return {
        "compliant": compliant,
        "score": round(passed / 6, 2),
        "signals_passed": passed,
        "signals_total": 6,
        "signals_detail": signals,
        "violations": violations,
        "flag": violations[0] if violations else None,
        "note": (
            "Surface-level RBI compliance check based on public disclosures. "
            "Full KFS document verification requires sandbox analysis."
        )
    }