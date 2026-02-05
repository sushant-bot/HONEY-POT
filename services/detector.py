# Scam Detection Service
from typing import List, Tuple

# Scam keyword categories
SCAM_KEYWORDS = {
    "urgency": [
        "immediately", "urgent", "now", "quick", "fast", "hurry",
        "asap", "within 24 hours", "today only", "last chance"
    ],
    "threat": [
        "blocked", "suspend", "freeze", "legal action", "police",
        "arrest", "court", "case", "fine", "penalty"
    ],
    "financial": [
        "upi", "bank", "account", "transfer", "payment",
        "money", "rupees", "rs", "inr"
    ],
    "authority": [
        "rbi", "reserve bank", "government", "customs",
        "income tax", "telecom", "trai"
    ],
    "reward": [
        "lottery", "prize", "winner", "congratulations",
        "won", "lucky", "reward", "cashback"
    ],
    "verification": [
        "verify", "kyc", "update", "aadhar", "pan",
        "otp", "link", "click"
    ]
}

# Minimum score to trigger scam detection
SCAM_THRESHOLD = 2


def is_scam_message(text: str) -> bool:
    """
    Check if message contains scam indicators.
    Returns True if scam score exceeds threshold.
    """
    score, _ = calculate_scam_score(text)
    return score >= SCAM_THRESHOLD


def calculate_scam_score(text: str) -> Tuple[int, List[str]]:
    """
    Calculate scam score and return matched categories.
    """
    text_lower = text.lower()
    score = 0
    matched_categories = []
    
    for category, keywords in SCAM_KEYWORDS.items():
        for keyword in keywords:
            if keyword in text_lower:
                score += 1
                if category not in matched_categories:
                    matched_categories.append(category)
                break  # Count each category only once
    
    return score, matched_categories


def check_urgency(text: str) -> bool:
    """Check if message contains urgency language."""
    text_lower = text.lower()
    return any(kw in text_lower for kw in SCAM_KEYWORDS["urgency"])


def check_payment_request(text: str) -> bool:
    """Check if message requests payment."""
    text_lower = text.lower()
    payment_phrases = [
        "send money", "transfer", "pay now", "payment required",
        "send rs", "send rupees", "upi id", "bank account"
    ]
    return any(phrase in text_lower for phrase in payment_phrases)


def check_threat(text: str) -> bool:
    """Check if message contains threats."""
    text_lower = text.lower()
    return any(kw in text_lower for kw in SCAM_KEYWORDS["threat"])


def get_scam_type(text: str, all_messages: List[str] = None) -> str:
    """
    Classify the scam type based on message content.
    """
    combined = text.lower()
    if all_messages:
        combined = " ".join(all_messages).lower()
    
    type_scores = {
        "UPI_FRAUD": 0,
        "ACCOUNT_SUSPENSION": 0,
        "KYC_UPDATE": 0,
        "LOTTERY_SCAM": 0,
        "TECH_SUPPORT_SCAM": 0
    }
    
    # UPI Fraud indicators
    upi_keywords = ["upi", "gpay", "phonepe", "paytm", "send money", "transfer"]
    type_scores["UPI_FRAUD"] = sum(1 for kw in upi_keywords if kw in combined)
    
    # Account Suspension indicators
    suspension_keywords = ["blocked", "suspend", "freeze", "deactivate", "restricted"]
    type_scores["ACCOUNT_SUSPENSION"] = sum(1 for kw in suspension_keywords if kw in combined)
    
    # KYC Update indicators
    kyc_keywords = ["kyc", "verify", "update", "aadhar", "pan", "documents"]
    type_scores["KYC_UPDATE"] = sum(1 for kw in kyc_keywords if kw in combined)
    
    # Lottery Scam indicators
    lottery_keywords = ["lottery", "prize", "winner", "congratulations", "won", "lucky"]
    type_scores["LOTTERY_SCAM"] = sum(1 for kw in lottery_keywords if kw in combined)
    
    # Tech Support indicators
    tech_keywords = ["virus", "hacked", "remote", "teamviewer", "anydesk"]
    type_scores["TECH_SUPPORT_SCAM"] = sum(1 for kw in tech_keywords if kw in combined)
    
    # Return highest scoring type
    max_type = max(type_scores, key=type_scores.get)
    if type_scores[max_type] > 0:
        return max_type
    return "UNKNOWN"
