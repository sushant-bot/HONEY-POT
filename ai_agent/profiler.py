# Scammer Behavior Profiler - Tracks scammer patterns
from typing import Dict, Any, List
from dataclasses import dataclass, field


@dataclass
class BehaviorProfile:
    """Profile of scammer behavior patterns."""
    urgency_score: float = 0.0          # How urgent their language is (0-1)
    aggression_score: float = 0.0       # How aggressive/threatening (0-1)
    payment_turn: int = -1              # Turn when payment was first requested
    total_messages: int = 0
    threat_count: int = 0
    payment_request_count: int = 0
    identity_claims: List[str] = field(default_factory=list)  # "bank officer", "RBI", etc.


# Urgency indicators
URGENCY_WORDS = [
    "immediately", "urgent", "now", "quick", "fast", "hurry",
    "asap", "within 24 hours", "today only", "last chance",
    "time is running out", "deadline", "expire"
]

# Threat indicators
THREAT_WORDS = [
    "blocked", "suspend", "freeze", "legal action", "police",
    "arrest", "court", "case", "fine", "penalty", "jail"
]

# Payment request indicators
PAYMENT_WORDS = [
    "send money", "transfer", "pay", "payment", "amount",
    "rupees", "rs", "inr", "deposit", "fee", "charges"
]

# Authority claims
AUTHORITY_CLAIMS = [
    "bank", "rbi", "reserve bank", "government", "police",
    "cyber cell", "income tax", "customs", "telecom"
]


def analyze_message(text: str, turn: int, profile: BehaviorProfile) -> BehaviorProfile:
    """
    Analyze a scammer message and update behavior profile.
    """
    text_lower = text.lower()
    profile.total_messages += 1
    
    # Calculate urgency score
    urgency_matches = sum(1 for word in URGENCY_WORDS if word in text_lower)
    if urgency_matches > 0:
        # Incremental update to urgency score
        new_urgency = min(urgency_matches / 3, 1.0)
        profile.urgency_score = max(profile.urgency_score, new_urgency)
    
    # Calculate aggression score
    threat_matches = sum(1 for word in THREAT_WORDS if word in text_lower)
    if threat_matches > 0:
        profile.threat_count += threat_matches
        new_aggression = min(threat_matches / 2, 1.0)
        profile.aggression_score = max(profile.aggression_score, new_aggression)
    
    # Track payment requests
    payment_matches = sum(1 for word in PAYMENT_WORDS if word in text_lower)
    if payment_matches > 0:
        profile.payment_request_count += 1
        if profile.payment_turn == -1:
            profile.payment_turn = turn
    
    # Track authority claims
    for claim in AUTHORITY_CLAIMS:
        if claim in text_lower and claim not in profile.identity_claims:
            profile.identity_claims.append(claim)
    
    return profile


def get_risk_score(profile: BehaviorProfile) -> float:
    """
    Calculate overall risk score from behavior profile.
    Higher = more likely a serious scam attempt.
    """
    score = 0.0
    
    # Urgency contributes up to 0.25
    score += profile.urgency_score * 0.25
    
    # Aggression contributes up to 0.25
    score += profile.aggression_score * 0.25
    
    # Early payment request is a red flag
    if 0 < profile.payment_turn <= 2:
        score += 0.2  # Requested payment very early
    elif profile.payment_turn > 0:
        score += 0.1
    
    # Multiple payment requests
    if profile.payment_request_count >= 3:
        score += 0.15
    elif profile.payment_request_count >= 1:
        score += 0.05
    
    # Authority claims
    if len(profile.identity_claims) >= 2:
        score += 0.15  # Claiming multiple authorities is suspicious
    elif len(profile.identity_claims) >= 1:
        score += 0.05
    
    return min(score, 1.0)


def get_behavior_summary(profile: BehaviorProfile) -> Dict[str, Any]:
    """
    Generate human-readable behavior summary.
    """
    return {
        "urgencyLevel": "high" if profile.urgency_score > 0.6 else "medium" if profile.urgency_score > 0.3 else "low",
        "aggressionLevel": "high" if profile.aggression_score > 0.6 else "medium" if profile.aggression_score > 0.3 else "low",
        "paymentRequestedAt": f"turn {profile.payment_turn}" if profile.payment_turn > 0 else "not yet",
        "identityClaims": profile.identity_claims or ["none"],
        "riskScore": round(get_risk_score(profile), 2)
    }
