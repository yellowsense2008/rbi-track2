import re

# Known Indian Payment Gateways often abused by fake loan apps
KNOWN_GATEWAYS = [
    "razorpay.com", "api.razorpay.com", "cashfree.com", "payu.in", 
    "instamojo.com", "ccavenue.com", "billdesk.com", "stripe.com", "paytm.in"
]

def extract_financial_arteries(network_traffic: list) -> dict:
    """
    Scans raw network traffic arrays for UPI VPAs and Payment Gateways.
    """
    extracted_upis = set()
    detected_gateways = set()
    
    # Standard Regex for Indian UPI Virtual Payment Addresses (e.g., scammer@ybl, fakebank@okhdfcbank)
    upi_pattern = re.compile(r'[a-zA-Z0-9.\-_]{3,256}@[a-zA-Z]{3,64}')

    if not network_traffic:
        return {"extracted_upis": list(extracted_upis), "detected_gateways": list(detected_gateways)}

    for domain in network_traffic:
        domain_str = str(domain).lower()
        
        # 1. Check for Payment Gateways
        for gw in KNOWN_GATEWAYS:
            if gw in domain_str:
                detected_gateways.add(gw)
                
        # 2. Extract UPI IDs
        # Sometimes MobSF catches raw URLs or parameter strings containing the VPA
        matches = upi_pattern.findall(domain_str)
        for match in matches:
            # Filter out standard emails to only keep likely UPI handles
            if not match.endswith((".com", ".in", ".org", ".net", ".gov")):
                extracted_upis.add(match)

    return {
        "extracted_upis": list(extracted_upis),
        "detected_gateways": list(detected_gateways)
    }