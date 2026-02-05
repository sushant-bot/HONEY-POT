# Honeypot API - State-Driven Agentic Honeypot
# Full Architecture with Intelligence Extraction & Behavior Profiling
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from enum import Enum
import re
import sys
import os
import requests

from fastapi import Depends
from pydantic import BaseModel
from dotenv import load_dotenv

# Load environment variables from parent directory
env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
load_dotenv(env_path)

from services.auth import api_key_auth
from services.server import app

# GUVI Callback Configuration
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# ============================================================
# LLM CONFIGURATION (Cost-Optimized: ~$0.002 per request)
# ============================================================

USE_LLM = True  # LLM ENABLED
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
print(f"[STARTUP] LLM Enabled: {USE_LLM}, API Key loaded: {bool(OPENAI_API_KEY)}")

# Cost-saving settings
LLM_CONFIG = {
    "model": "gpt-3.5-turbo",  # Cheapest: $0.0005/1K input, $0.0015/1K output
    "temperature": 0.3,         # Low = consistent responses
    "max_tokens": 40,           # Short responses only (saves tokens)
}
# sushant chat dekh h kap

SYSTEM_PROMPT = """You are a worried 45-year-old Indian person who is not tech-savvy.
Rules:
- Sound scared and confused
- Ask only ONE short question
- Under 20 words
- NEVER say: scam, fraud, police, fake, bot, AI, report, suspicious
- Use phrases like: sir, please help, I don't understand"""

def get_llm_reply(state: str, scammer_message: str, intent: str) -> Optional[str]:
    """Generate reply using LLM. Returns None if fails."""
    if not OPENAI_API_KEY or not USE_LLM:
        return None
    
    try:
        import openai
        client = openai.OpenAI(api_key=OPENAI_API_KEY)
        
        user_prompt = f"Scammer said: \"{scammer_message[:100]}\"\nYour intent: {intent}\nRespond naturally:"
        
        response = client.chat.completions.create(
            model=LLM_CONFIG["model"],
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt}
            ],
            temperature=LLM_CONFIG["temperature"],
            max_tokens=LLM_CONFIG["max_tokens"]
        )
        
        reply = response.choices[0].message.content.strip()
        
        # Safety check - reject if contains forbidden words
        forbidden = ["scam", "fraud", "police", "fake", "bot", "ai", "report", "suspicious"]
        if any(word in reply.lower() for word in forbidden):
            return None
        
        return reply
    except Exception as e:
        print(f"LLM Error: {e}")
        return None


# ============================================================
# AGENT STATE MACHINE
# ============================================================

class AgentState(Enum):
    """Agent states in the honeypot conversation."""
    INIT = "INIT"
    CONFUSED = "CONFUSED"
    TRUSTING = "TRUSTING"
    COMPLIANT = "COMPLIANT"
    EXTRACTION = "EXTRACTION"
    EXIT = "EXIT"


def get_next_state(
    current_state: AgentState,
    turn_count: int,
    has_payment_request: bool,
    intelligence_count: int,
    max_turns: int = 10
) -> AgentState:
    """Determine next agent state (DETERMINISTIC - no AI)."""
    if turn_count >= max_turns:
        return AgentState.EXIT
    if intelligence_count >= 3 and current_state == AgentState.EXTRACTION:
        return AgentState.EXIT
    
    if current_state == AgentState.INIT:
        return AgentState.CONFUSED
    elif current_state == AgentState.CONFUSED:
        return AgentState.TRUSTING if turn_count >= 2 else AgentState.CONFUSED
    elif current_state == AgentState.TRUSTING:
        return AgentState.COMPLIANT if (has_payment_request or turn_count >= 4) else AgentState.TRUSTING
    elif current_state == AgentState.COMPLIANT:
        return AgentState.EXTRACTION if turn_count >= 5 else AgentState.COMPLIANT
    elif current_state == AgentState.EXTRACTION:
        return AgentState.EXIT if (intelligence_count >= 2 or turn_count >= 8) else AgentState.EXTRACTION
    return current_state


# ============================================================
# BEHAVIOR PROFILER
# ============================================================

@dataclass
class BehaviorProfile:
    """Scammer behavior patterns."""
    urgency_score: float = 0.0
    aggression_score: float = 0.0
    payment_turn: int = -1
    total_messages: int = 0
    threat_count: int = 0
    payment_request_count: int = 0
    identity_claims: List[str] = field(default_factory=list)


URGENCY_WORDS = ["immediately", "urgent", "now", "quick", "fast", "hurry", "asap", "within 24 hours", "today only"]
THREAT_WORDS = ["blocked", "suspend", "freeze", "legal action", "police", "arrest", "court", "case", "fine"]
PAYMENT_WORDS = ["send money", "transfer", "pay", "payment", "amount", "rupees", "rs", "inr", "deposit"]
AUTHORITY_CLAIMS = ["bank", "rbi", "reserve bank", "government", "police", "cyber cell", "income tax"]


def analyze_behavior(text: str, turn: int, profile: BehaviorProfile) -> BehaviorProfile:
    """Analyze scammer message and update behavior profile."""
    text_lower = text.lower()
    profile.total_messages += 1
    
    urgency_matches = sum(1 for w in URGENCY_WORDS if w in text_lower)
    if urgency_matches > 0:
        profile.urgency_score = max(profile.urgency_score, min(urgency_matches / 3, 1.0))
    
    threat_matches = sum(1 for w in THREAT_WORDS if w in text_lower)
    if threat_matches > 0:
        profile.threat_count += threat_matches
        profile.aggression_score = max(profile.aggression_score, min(threat_matches / 2, 1.0))
    
    payment_matches = sum(1 for w in PAYMENT_WORDS if w in text_lower)
    if payment_matches > 0:
        profile.payment_request_count += 1
        if profile.payment_turn == -1:
            profile.payment_turn = turn
    
    for claim in AUTHORITY_CLAIMS:
        if claim in text_lower and claim not in profile.identity_claims:
            profile.identity_claims.append(claim)
    
    return profile


def get_risk_score(profile: BehaviorProfile) -> float:
    """Calculate overall risk score from behavior profile."""
    score = profile.urgency_score * 0.25 + profile.aggression_score * 0.25
    if 0 < profile.payment_turn <= 2:
        score += 0.2
    elif profile.payment_turn > 0:
        score += 0.1
    if profile.payment_request_count >= 3:
        score += 0.15
    if len(profile.identity_claims) >= 2:
        score += 0.15
    return min(score, 1.0)


def get_behavior_summary(profile: BehaviorProfile) -> Dict[str, Any]:
    """Generate behavior summary for callback."""
    return {
        "urgencyLevel": "high" if profile.urgency_score > 0.6 else "medium" if profile.urgency_score > 0.3 else "low",
        "aggressionLevel": "high" if profile.aggression_score > 0.6 else "medium" if profile.aggression_score > 0.3 else "low",
        "paymentRequestedAt": f"turn {profile.payment_turn}" if profile.payment_turn > 0 else "not yet",
        "identityClaims": profile.identity_claims or ["none"],
        "riskScore": round(get_risk_score(profile), 2)
    }


# ============================================================
# INTELLIGENCE EXTRACTION
# ============================================================

@dataclass
class ExtractedIntel:
    """Single piece of extracted intelligence."""
    type: str
    value: str
    confidence: float
    source_turn: int
    context: str


def extract_upi_ids(text: str) -> List[str]:
    pattern = r"\b[\w.-]+@[a-zA-Z]{2,}\b"
    return re.findall(pattern, text)


def extract_phone_numbers(text: str) -> List[str]:
    # Match Indian phone numbers with or without +91 prefix
    patterns = [
        r"\+91\s?[6-9]\d{9}\b",  # +91 format
        r"\b[6-9]\d{9}\b"         # 10-digit format
    ]
    results = []
    for pattern in patterns:
        results.extend(re.findall(pattern, text))
    return list(set(results))


def extract_bank_accounts(text: str) -> List[str]:
    """Extract bank account numbers from text."""
    # First, remove phone numbers from text to avoid false positives
    text_clean = re.sub(r'\+91\s?[6-9]\d{9}', '', text)  # Remove +91 format phones
    text_clean = re.sub(r'\b[6-9]\d{9}\b', '', text_clean)  # Remove 10-digit phones
    
    patterns = [
        r"\b\d{4}[-\s]\d{4}[-\s]\d{4}(?:[-\s]\d{0,4})?\b",  # XXXX-XXXX-XXXX format
        r"\b\d{11,16}\b",  # 11-16 digit account numbers (avoid 10-digit phones)
    ]
    results = []
    for pattern in patterns:
        matches = re.findall(pattern, text_clean)
        for match in matches:
            # Clean value
            clean = match.strip()
            clean_digits = re.sub(r'[-\s]', '', clean)
            # Must have at least 11 digits to avoid phone number overlap
            if len(clean_digits) >= 11 and len(clean_digits) <= 18:
                results.append(clean)
    return list(set(results))


def extract_links(text: str) -> List[str]:
    pattern = r"https?://[^\s<>\"{}|\\^`\[\]]+"
    links = re.findall(pattern, text)
    # Clean trailing punctuation
    cleaned = []
    for link in links:
        cleaned.append(link.rstrip('!.,;:?'))
    return list(set(cleaned))


def extract_all(text: str, turn: int) -> Dict[str, List[ExtractedIntel]]:
    """Extract all intelligence from message."""
    result = {"upiIds": [], "phoneNumbers": [], "links": [], "bankAccounts": []}
    
    def get_context(value: str, full_text: str) -> str:
        idx = full_text.lower().find(value.lower())
        if idx == -1:
            return full_text[:50]
        return full_text[max(0, idx-20):min(len(full_text), idx+len(value)+30)]
    
    for upi in extract_upi_ids(text):
        result["upiIds"].append(ExtractedIntel("upi", upi, 0.9, turn, get_context(upi, text)))
    for phone in extract_phone_numbers(text):
        result["phoneNumbers"].append(ExtractedIntel("phone", phone, 0.85, turn, get_context(phone, text)))
    for link in extract_links(text):
        result["links"].append(ExtractedIntel("link", link, 0.95, turn, get_context(link, text)))
    for account in extract_bank_accounts(text):
        result["bankAccounts"].append(ExtractedIntel("bank", account, 0.8, turn, get_context(account, text)))
    
    return result


# ============================================================
# SESSION & GLOBAL TRACKING
# ============================================================

@dataclass
class ChatMessage:
    """Single message in conversation."""
    role: str  # "scammer" or "agent"
    content: str
    turn: int
    timestamp: Optional[int] = None

@dataclass
class Session:
    """Conversation session."""
    session_id: str
    state: AgentState = AgentState.INIT
    turns: int = 0
    scam_detected: bool = False
    scam_type: Optional[str] = None
    all_messages: List[str] = field(default_factory=list)
    chat_history: List[ChatMessage] = field(default_factory=list)  # Full conversation
    intelligence: Dict[str, List[Dict]] = field(default_factory=lambda: {"upiIds": [], "phoneNumbers": [], "links": [], "bankAccounts": []})
    behavior_profile: BehaviorProfile = field(default_factory=BehaviorProfile)
    is_complete: bool = False


sessions: Dict[str, Session] = {}
global_intel_tracker = {"upiIds": {}, "phoneNumbers": {}, "links": {}, "bankAccounts": {}}


def get_or_create_session(session_id: str) -> Session:
    if session_id not in sessions:
        sessions[session_id] = Session(session_id=session_id)
    return sessions[session_id]


def track_global_intel(session_id: str, intel: Dict[str, List]) -> None:
    for intel_type in ["upiIds", "phoneNumbers", "links", "bankAccounts"]:
        for item in intel.get(intel_type, []):
            value = item["value"] if isinstance(item, dict) else item
            if value not in global_intel_tracker[intel_type]:
                global_intel_tracker[intel_type][value] = []
            if session_id not in global_intel_tracker[intel_type][value]:
                global_intel_tracker[intel_type][value].append(session_id)


def get_cross_session_links(intel: Dict[str, List]) -> Dict[str, Dict[str, int]]:
    linked = {"upiIds": {}, "phoneNumbers": {}, "links": {}, "bankAccounts": {}}
    for intel_type in ["upiIds", "phoneNumbers", "links", "bankAccounts"]:
        for item in intel.get(intel_type, []):
            value = item["value"] if isinstance(item, dict) else item
            sessions_list = global_intel_tracker[intel_type].get(value, [])
            if len(sessions_list) > 1:
                linked[intel_type][value] = len(sessions_list)
    return linked


# ============================================================
# SCAM DETECTION & CLASSIFICATION
# ============================================================

SCAM_KEYWORDS = ["blocked", "verify", "urgent", "suspend", "account", "upi", "bank", "lottery", "prize"]
SCAM_TYPE_PATTERNS = {
    "UPI_FRAUD": ["upi", "gpay", "phonepe", "paytm", "send money", "transfer"],
    "ACCOUNT_SUSPENSION": ["blocked", "suspend", "deactivate", "freeze", "restricted"],
    "KYC_UPDATE": ["kyc", "verify", "update", "aadhar", "pan", "documents"],
    "LOTTERY_SCAM": ["lottery", "prize", "winner", "congratulations", "won", "lucky"]
}


def is_scam_message(text: str) -> bool:
    text_lower = text.lower()
    return any(kw in text_lower for kw in SCAM_KEYWORDS)


def classify_scam_type(messages: List[str]) -> str:
    combined = " ".join(messages).lower()
    scores = {st: sum(1 for kw in kws if kw in combined) for st, kws in SCAM_TYPE_PATTERNS.items()}
    return max(scores, key=scores.get) if max(scores.values()) > 0 else "UNKNOWN"


# ============================================================
# CONFIDENCE & CALLBACK
# ============================================================

def calculate_agent_confidence(session: Session) -> float:
    confidence = 0.3 if session.scam_detected else 0.0
    intel_count = sum(len(session.intelligence.get(k, [])) for k in ["upiIds", "phoneNumbers", "links", "bankAccounts"])
    confidence += min(intel_count * 0.1, 0.3)
    if session.behavior_profile.urgency_score > 0.5:
        confidence += 0.1
    if session.behavior_profile.payment_turn > 0:
        confidence += 0.1
    if session.behavior_profile.threat_count > 0:
        confidence += 0.1
    return min(round(confidence, 2), 1.0)


def extract_suspicious_keywords(messages: List[str]) -> List[str]:
    """Extract suspicious keywords from conversation."""
    suspicious = [
        "urgent", "verify now", "account blocked", "immediately", 
        "suspended", "freeze", "otp", "share", "transfer", 
        "kyc", "update", "expire", "deadline", "penalty"
    ]
    found = set()
    text = " ".join(messages).lower()
    for keyword in suspicious:
        if keyword in text:
            found.add(keyword)
    return list(found)


def build_callback_payload(session: Session, cross_links: Dict) -> Dict[str, Any]:
    """Build GUVI-compliant callback payload."""
    # Extract values into GUVI format
    bank_accounts = [item["value"] for item in session.intelligence.get("bankAccounts", [])]
    upi_ids = [item["value"] for item in session.intelligence.get("upiIds", [])]
    
    # Format phone numbers with +91 prefix as per GUVI spec
    raw_phones = [item["value"] for item in session.intelligence.get("phoneNumbers", [])]
    phone_numbers = []
    for phone in raw_phones:
        if phone.startswith("+91"):
            phone_numbers.append(phone)
        else:
            phone_numbers.append(f"+91{phone}")
    
    phishing_links = [item["value"] for item in session.intelligence.get("links", [])]
    suspicious_keywords = extract_suspicious_keywords(session.all_messages)
    
    # Build agent notes from behavior profile
    behavior = session.behavior_profile
    notes_parts = []
    if behavior.urgency_score > 0.5:
        notes_parts.append("Scammer used urgency tactics")
    if behavior.payment_turn > 0:
        notes_parts.append("payment redirection attempted")
    if behavior.threat_count > 0:
        notes_parts.append("threats detected")
    if behavior.identity_claims:
        notes_parts.append(f"claimed to be {', '.join(behavior.identity_claims)}")
    agent_notes = ". ".join(notes_parts) if notes_parts else "Standard scam engagement completed"
    
    # GUVI-compliant payload
    return {
        "sessionId": session.session_id,
        "scamDetected": session.scam_detected,
        "totalMessagesExchanged": len(session.chat_history),
        "extractedIntelligence": {
            "bankAccounts": bank_accounts,
            "upiIds": upi_ids,
            "phishingLinks": phishing_links,
            "phoneNumbers": phone_numbers,
            "suspiciousKeywords": suspicious_keywords
        },
        "agentNotes": agent_notes
    }


def send_guvi_callback(payload: Dict[str, Any]) -> bool:
    """Send final result to GUVI evaluation endpoint."""
    try:
        print(f"\n{'='*50}")
        print("📡 SENDING TO GUVI CALLBACK:")
        print(f"URL: {GUVI_CALLBACK_URL}")
        print(f"Payload: {payload}")
        
        response = requests.post(
            GUVI_CALLBACK_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        print(f"Response Status: {response.status_code}")
        print(f"Response Body: {response.text}")
        print("="*50 + "\n")
        
        return response.status_code == 200
    except Exception as e:
        print(f"❌ GUVI Callback Error: {e}")
        return False


# ============================================================
# REPLY GENERATION (LLM + Fallback)
# ============================================================

STATE_REPLIES = {
    "INIT": ["Sir, what is happening? I don't understand."],
    "CONFUSED": ["But why is my account blocked? I didn't do anything wrong.", "Sir, please explain. What mistake have I made?"],
    "TRUSTING": ["Okay sir, please tell me what I need to do.", "I am very worried. Please help me fix this."],
    "COMPLIANT": ["Okay, I will do as you say. Where should I send the money?", "Please give me the details."],
    "EXTRACTION": ["Can you share the payment details again?", "What is your phone number so I can confirm?"],
    "EXIT": ["Okay sir, I will do it in some time. Thank you.", "Let me think about this. I will call you back."]
}

STATE_INTENTS = {
    "INIT": "express confusion about what is happening",
    "CONFUSED": "ask why the account is blocked",
    "TRUSTING": "ask what steps are needed to fix this",
    "COMPLIANT": "agree to help and ask for payment details",
    "EXTRACTION": "ask for UPI or phone number to confirm",
    "EXIT": "politely say you will do it later"
}

def get_reply(state: AgentState, turn: int, scammer_message: str = "") -> str:
    """Get reply - tries LLM first, falls back to deterministic."""
    state_name = state.value
    intent = STATE_INTENTS.get(state_name, "express confusion")
    
    # Try LLM first (if enabled)
    if USE_LLM and scammer_message:
        llm_reply = get_llm_reply(state_name, scammer_message, intent)
        if llm_reply:
            print(f"  [LLM] Generated: {llm_reply}")
            return llm_reply
    
    # Fallback to deterministic
    replies = STATE_REPLIES.get(state_name, STATE_REPLIES["CONFUSED"])
    fallback = replies[turn % len(replies)]
    print(f"  [Fallback] Using: {fallback}")
    return fallback


# ============================================================
# API MODELS (GUVI Spec Compliant)
# ============================================================

class Message(BaseModel):
    sender: str
    text: str
    timestamp: Optional[int] = None


class HistoryMessage(BaseModel):
    sender: str
    text: str
    timestamp: Optional[int] = None


class Metadata(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = "English"
    locale: Optional[str] = "IN"


class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: Optional[List[HistoryMessage]] = []
    metadata: Optional[Metadata] = None


class HoneypotResponse(BaseModel):
    """GUVI expects only status + reply. Extra fields are optional."""
    status: str
    reply: str


# ============================================================
# MAIN ENDPOINT
# ============================================================

MAX_TURNS = 10


@app.post("/api/honeypot", response_model=HoneypotResponse)
def honeypot_endpoint(
    payload: HoneypotRequest,
    _api_key: str = Depends(api_key_auth),
):
    """Main honeypot endpoint - State-driven agentic conversation."""
    session_id = payload.sessionId
    sender = payload.message.sender
    text = payload.message.text
    
    # Get or create session
    session = get_or_create_session(session_id)
    session.all_messages.append(text)
    
    # Store scammer message in chat history
    session.chat_history.append(ChatMessage(
        role="scammer",
        content=text,
        turn=session.turns + 1,
        timestamp=payload.message.timestamp
    ))
    
    # Already complete
    if session.is_complete:
        return HoneypotResponse(status="success", reply="Thank you, I will check this later.")
    
    # Process scammer messages
    if sender == "scammer":
        session.turns += 1
        
        # Extract intelligence
        extracted = extract_all(text, session.turns)
        for intel_type in ["upiIds", "phoneNumbers", "links", "bankAccounts"]:
            for item in extracted.get(intel_type, []):
                session.intelligence[intel_type].append({
                    "value": item.value,
                    "confidence": item.confidence,
                    "source_turn": item.source_turn,
                    "context": item.context
                })
        
        # Track globally
        track_global_intel(session_id, session.intelligence)
        
        # Analyze behavior
        session.behavior_profile = analyze_behavior(text, session.turns, session.behavior_profile)
        
        # Scam detection
        if not session.scam_detected:
            if is_scam_message(text):
                session.scam_detected = True
                session.scam_type = classify_scam_type(session.all_messages)
            else:
                return HoneypotResponse(status="success", reply="Okay, I understand.")
        
        # Update scam type
        session.scam_type = classify_scam_type(session.all_messages)
        
        # Update state
        intel_count = sum(len(session.intelligence.get(k, [])) for k in ["upiIds", "phoneNumbers", "links", "bankAccounts"])
        session.state = get_next_state(
            session.state, session.turns,
            session.behavior_profile.payment_turn > 0,
            intel_count, MAX_TURNS
        )
        
        # Generate reply (LLM or fallback)
        reply_text = get_reply(session.state, session.turns, text)
        agent_confidence = calculate_agent_confidence(session)
        cross_links = get_cross_session_links(session.intelligence)
        
        # Store agent reply in chat history
        session.chat_history.append(ChatMessage(
            role="agent",
            content=reply_text,
            turn=session.turns
        ))
        
        # Log progress
        print(f"[Turn {session.turns}] State: {session.state.value}, Intel: {intel_count}, Confidence: {agent_confidence}")
        
        # Check exit - send GUVI callback
        if session.state == AgentState.EXIT:
            session.is_complete = True
            callback = build_callback_payload(session, cross_links)
            
            # Send to GUVI evaluation endpoint
            send_guvi_callback(callback)
            
            return HoneypotResponse(status="success", reply=reply_text)
        
        return HoneypotResponse(status="success", reply=reply_text)
    
    # Non-scammer
    return HoneypotResponse(status="success", reply="Okay.")


@app.get("/")
def root():
    """Landing page."""
    return {
        "service": "🍯 Honeypot API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
        "endpoints": {
            "honeypot": "POST /api/honeypot",
            "session": "GET /api/session/{id}",
            "chat": "GET /api/chat/{id}",
            "health": "GET /health"
        }
    }


@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "honeypot-api"}


@app.get("/api/session/{session_id}")
def get_session_info(session_id: str, _api_key: str = Depends(api_key_auth)):
    """Debug endpoint to view session state."""
    session = get_or_create_session(session_id)
    return {
        "sessionId": session.session_id,
        "state": session.state.value,
        "turns": session.turns,
        "scamDetected": session.scam_detected,
        "scamType": session.scam_type,
        "intelligence": session.intelligence,
        "behaviorProfile": get_behavior_summary(session.behavior_profile),
        "isComplete": session.is_complete,
        "chatHistory": [
            {"role": msg.role, "content": msg.content, "turn": msg.turn, "timestamp": msg.timestamp}
            for msg in session.chat_history
        ]
    }


@app.get("/api/chat/{session_id}")
def get_chat_history(session_id: str, _api_key: str = Depends(api_key_auth)):
    """Get full conversation history for a session."""
    if session_id not in sessions:
        return {"error": "Session not found", "sessionId": session_id}
    
    session = sessions[session_id]
    
    # Format as readable conversation
    conversation = []
    for msg in session.chat_history:
        conversation.append({
            "turn": msg.turn,
            "speaker": "🔴 Scammer" if msg.role == "scammer" else "🤖 Agent",
            "message": msg.content,
            "timestamp": msg.timestamp
        })
    
    return {
        "sessionId": session_id,
        "totalTurns": session.turns,
        "scamType": session.scam_type,
        "intelligenceExtracted": session.intelligence,
        "conversation": conversation
    }


