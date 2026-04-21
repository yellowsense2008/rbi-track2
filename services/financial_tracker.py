import re

KNOWN_GATEWAYS = [
    "razorpay.com", "api.razorpay.com", "cashfree.com", "payu.in",
    "instamojo.com", "ccavenue.com", "billdesk.com", "stripe.com", "paytm.in"
]

# Non-standard TLDs that are internal SDK endpoints, never resolve on public internet
NON_STANDARD_TLDS = ['.s', '.local', '.internal', '.sdk', '.test', '.dev.s']

def is_resolvable_domain(domain: str) -> bool:
    """Filter out internal SDK beacon endpoints that MobSF captures but never resolve."""
    for tld in NON_STANDARD_TLDS:
        if domain.lower().endswith(tld):
            return False
    return True

def extract_financial_arteries(network_traffic: list) -> dict:
    extracted_upis = set()
    detected_gateways = set()

    upi_pattern = re.compile(r'[a-zA-Z0-9.\-_]{3,256}@[a-zA-Z]{3,64}')

    if not network_traffic:
        return {"extracted_upis": [], "detected_gateways": []}

    for domain in network_traffic:
        domain_str = str(domain).lower()

        # Skip unresolvable internal SDK endpoints
        if not is_resolvable_domain(domain_str):
            continue

        for gw in KNOWN_GATEWAYS:
            if gw in domain_str:
                detected_gateways.add(gw)

        matches = upi_pattern.findall(domain_str)
        for match in matches:
            if not match.endswith((".com", ".in", ".org", ".net", ".gov")):
                extracted_upis.add(match)

    return {
        "extracted_upis": list(extracted_upis),
        "detected_gateways": list(detected_gateways)
    }