# Intelligence Confidence Model - Scores and correlates intelligence
from typing import Dict, List, Any
from dataclasses import dataclass


@dataclass
class ScoredIntelligence:
    """Intelligence with confidence scoring."""
    type: str
    value: str
    base_confidence: float
    boosted_confidence: float
    source_turn: int
    context: str
    cross_session_count: int = 0


def boost_confidence(
    base_confidence: float,
    urgency_score: float,
    early_payment: bool,
    cross_session_count: int
) -> float:
    """
    Boost intelligence confidence based on behavioral signals.
    """
    boosted = base_confidence
    
    # High urgency = scammer is serious
    if urgency_score > 0.5:
        boosted += 0.05
    
    # Early payment request = clear intent
    if early_payment:
        boosted += 0.05
    
    # Cross-session reuse = confirmed scammer
    if cross_session_count > 1:
        boosted += 0.1 * min(cross_session_count - 1, 3)
    
    return min(boosted, 1.0)


def calculate_agent_confidence(session_data: Dict) -> float:
    """
    Calculate overall agent confidence in scam detection.
    Based on multiple signals.
    """
    confidence = 0.0
    
    # Base confidence if scam detected
    if session_data.get("scam_detected"):
        confidence += 0.3
    
    # Intelligence extracted
    intel = session_data.get("intelligence", {})
    intel_count = sum(len(intel.get(k, [])) for k in ["upiIds", "phoneNumbers", "links"])
    confidence += min(intel_count * 0.1, 0.3)
    
    # Behavior profile signals
    profile = session_data.get("behavior_profile", {})
    if profile.get("urgency_score", 0) > 0.5:
        confidence += 0.1
    if profile.get("payment_turn", -1) > 0:
        confidence += 0.1
    if profile.get("threat_count", 0) > 0:
        confidence += 0.1
    
    # Cross-session correlation
    cross_links = session_data.get("cross_session_links", {})
    if any(cross_links.values()):
        confidence += 0.1
    
    return min(round(confidence, 2), 1.0)


def classify_scam_type(messages: List[str]) -> str:
    """
    Classify the scam type based on all messages.
    """
    combined = " ".join(messages).lower()
    
    type_patterns = {
        "UPI_FRAUD": ["upi", "gpay", "phonepe", "paytm", "send money", "transfer"],
        "ACCOUNT_SUSPENSION": ["blocked", "suspend", "deactivate", "freeze", "restricted"],
        "KYC_UPDATE": ["kyc", "verify", "update", "aadhar", "pan", "documents"],
        "LOTTERY_SCAM": ["lottery", "prize", "winner", "congratulations", "won", "lucky"],
        "TECH_SUPPORT": ["virus", "hacked", "remote", "teamviewer", "anydesk"],
        "LOAN_FRAUD": ["loan", "emi", "credit", "pre-approved", "instant loan"]
    }
    
    scores = {}
    for scam_type, keywords in type_patterns.items():
        score = sum(1 for kw in keywords if kw in combined)
        scores[scam_type] = score
    
    if max(scores.values()) > 0:
        return max(scores, key=scores.get)
    return "UNKNOWN"


def generate_intel_report(session_data: Dict) -> Dict[str, Any]:
    """
    Generate structured intelligence report for final callback.
    """
    intel = session_data.get("intelligence", {})
    
    # Format intelligence with confidence
    formatted_intel = []
    for intel_type in ["upiIds", "phoneNumbers", "links", "bankAccounts", "ifscCodes"]:
        for item in intel.get(intel_type, []):
            if isinstance(item, dict):
                formatted_intel.append({
                    "type": intel_type,
                    "value": item.get("value", str(item)),
                    "confidence": item.get("confidence", 0.8)
                })
            else:
                formatted_intel.append({
                    "type": intel_type,
                    "value": str(item),
                    "confidence": 0.8
                })
    
    return {
        "extractedIntelligence": formatted_intel,
        "totalItems": len(formatted_intel),
        "scamType": session_data.get("scam_type", "UNKNOWN"),
        "agentConfidence": calculate_agent_confidence(session_data)
    }
