import requests

# --- TRUE INDIC DEEPTECH CONFIGURATION ---
HF_MODEL_ID = "l3cube-pune/indic-sentence-similarity-sbert"
HF_API_URL = f"https://router.huggingface.co/hf-inference/models/{HF_MODEL_ID}"

# Your Hugging Face Access Token
import os
HF_TOKEN = os.getenv("HUGGINGFACE_API_KEY")

# The Ground Truth Corporate Identities
OFFICIAL_ENTITIES = {
    "sbi": "State Bank of India official application. Secure digital banking, YONO, and financial services.",
    "bajaj": "Bajaj Finance Limited and Bajaj Finserv. Official NBFC offering fixed deposits, EMI cards, and secure personal loans.",
    "hdfc": "HDFC Bank MobileBanking official app for secure transactions and loans."
}

# Authorized developer aliases for the Fallback check
AUTHORIZED_DEVS = {
    "sbi": ["state bank of india", "sbi"],
    "bajaj": ["bajaj finance limited", "bajaj finserv"],
    "hdfc": ["hdfc bank ltd", "hdfc bank"]
}

# Predatory phrases natively understood across 10 Indian languages by IndicSBERT
PREDATORY_PHRASES = [
    "guaranteed instant approval no credit check",
    "bina cibil score ke loan", 
    "kahihi documents nastaana loan", 
    "100% approval zero documentation apply now"
]

def get_hf_similarity_scores(source: str, targets: list) -> list:
    """
    Sends texts to Hugging Face to calculate semantic similarity on their GPUs.
    """
    if not source or not targets or not HF_TOKEN or not HF_TOKEN.startswith("hf_"):
        return []

    headers = {"Authorization": f"Bearer {HF_TOKEN}"}
    
    # The exact payload structure the HF Sentence Similarity pipeline demands
    payload = {
        "inputs": {
            "source_sentence": source,
            "sentences": targets
        }
    }
    
    try:
        response = requests.post(HF_API_URL, headers=headers, json=payload, timeout=10)
        
        if response.status_code == 200:
            # Returns a clean list of floats, e.g., [0.85, 0.12, 0.99]
            return response.json()
        elif response.status_code == 503:
            print("HF API Warning: Model is waking up. Try again in 20 seconds.")
        else:
            print(f"HF API Warning: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"HF API Network Error: {e}")
        
    return []

def detect_brand_impersonation(app_title: str, developer_name: str, description: str) -> dict:
    """
    Analyzes metadata for Corporate Identity Hijacking using Hugging Face IndicSBERT.
    """
    app_title = (app_title or "").lower()
    developer_name = (developer_name or "").lower()
    description = (description or "").lower()
    
    combined_text = f"{app_title}. {description}"
    
    impersonation_flags = []
    risk_score = 0.0
    active_engine = "Local Keyword Fallback" # Assumes fallback until HF succeeds

    # 1. Catch Brand Cloning (The Semantic Disconnect)
    for bank_key, official_context in OFFICIAL_ENTITIES.items():
        if bank_key in combined_text:
            
            # Ask HF to compare the app text against the official bank description
            scores = get_hf_similarity_scores(combined_text, [official_context])
            
            if scores:
                active_engine = "IndicSBERT DeepTech (Hugging Face)"
                context_match_score = scores[0]
                
                if context_match_score < 0.40:
                    impersonation_flags.append({
                        "signal": f"Semantic Disconnect: Claims association with {bank_key.upper()} but linguistic context does not match.",
                        "weight": 0.50
                    })
                    risk_score += 0.50
            else:
                # FALLBACK: If HF is asleep or fails
                authorized_list = AUTHORIZED_DEVS.get(bank_key, [bank_key])
                if not any(auth in developer_name for auth in authorized_list):
                    impersonation_flags.append({
                        "signal": f"Identity Mismatch (Fallback): Claims '{bank_key.upper()}' but developer is '{developer_name}'",
                        "weight": 0.50
                    })
                    risk_score += 0.50

    # 2. Catch Predatory Intent
    # We compare the app text against ALL predatory phrases in one single API call
    predatory_scores = get_hf_similarity_scores(combined_text, PREDATORY_PHRASES)
    
    if predatory_scores:
        active_engine = "IndicSBERT DeepTech (Hugging Face)"
        highest_predatory_match = max(predatory_scores)

        if highest_predatory_match > 0.65:
            impersonation_flags.append({
                "signal": f"High Predatory Intent Detected (IndicSBERT Match: {highest_predatory_match*100:.1f}%)",
                "weight": 0.40
            })
            risk_score += 0.40
    else:
        # FALLBACK
        fallback_keywords = ["instant approval", "no credit check", "urgent cash", "without cibil"]
        found_keywords = [kw for kw in fallback_keywords if kw in description]
        if found_keywords:
            impersonation_flags.append({
                "signal": f"Predatory Marketing Detected (Fallback check): {', '.join(found_keywords)}",
                "weight": 0.30
            })
            risk_score += 0.30

    return {
        "nlp_risk_score": min(risk_score, 1.0),
        "nlp_flags": impersonation_flags,
        "engine_used": active_engine
    }