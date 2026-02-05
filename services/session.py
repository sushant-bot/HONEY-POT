# Session Lifecycle Management
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from ai_agent.state_machine import AgentState
from ai_agent.profiler import BehaviorProfile


@dataclass
class Session:
    """Represents a honeypot conversation session."""
    session_id: str
    state: AgentState = AgentState.INIT
    turns: int = 0
    scam_detected: bool = False
    scam_type: Optional[str] = None
    all_messages: list = field(default_factory=list)
    intelligence: Dict[str, list] = field(default_factory=lambda: {
        "upiIds": [],
        "phoneNumbers": [],
        "links": [],
        "bankAccounts": [],
        "ifscCodes": []
    })
    behavior_profile: BehaviorProfile = field(default_factory=BehaviorProfile)
    urgency_detected: bool = False
    payment_requested: bool = False
    is_complete: bool = False


# In-memory session store
sessions: Dict[str, Session] = {}

# Global intelligence tracker for cross-session linking
global_intel_tracker = {
    "upiIds": {},       # value -> [session_ids]
    "phoneNumbers": {},
    "links": {}
}


def get_or_create_session(session_id: str) -> Session:
    """Get existing session or create new one."""
    if session_id not in sessions:
        sessions[session_id] = Session(session_id=session_id)
    return sessions[session_id]


def get_session(session_id: str) -> Optional[Session]:
    """Get session by ID, returns None if not found."""
    return sessions.get(session_id)


def update_session(session: Session) -> None:
    """Update session in store."""
    sessions[session.session_id] = session


def mark_session_complete(session_id: str) -> None:
    """Mark session as complete (agent exited)."""
    if session_id in sessions:
        sessions[session_id].is_complete = True


def track_global_intel(session_id: str, intel: Dict[str, list]) -> None:
    """Track intelligence globally for cross-session correlation."""
    for intel_type in ["upiIds", "phoneNumbers", "links"]:
        for item in intel.get(intel_type, []):
            value = item if isinstance(item, str) else item.get("value", str(item))
            if value not in global_intel_tracker[intel_type]:
                global_intel_tracker[intel_type][value] = []
            if session_id not in global_intel_tracker[intel_type][value]:
                global_intel_tracker[intel_type][value].append(session_id)


def get_cross_session_links(intel: Dict[str, list]) -> Dict[str, Dict[str, int]]:
    """Get cross-session occurrences for intelligence."""
    linked = {
        "upiIds": {},
        "phoneNumbers": {},
        "links": {}
    }
    
    for intel_type in ["upiIds", "phoneNumbers", "links"]:
        for item in intel.get(intel_type, []):
            value = item if isinstance(item, str) else item.get("value", str(item))
            sessions_list = global_intel_tracker[intel_type].get(value, [])
            if len(sessions_list) > 1:
                linked[intel_type][value] = len(sessions_list)
    
    return linked


def session_to_dict(session: Session) -> Dict[str, Any]:
    """Convert session to dictionary for API response."""
    return {
        "sessionId": session.session_id,
        "state": session.state.value,
        "turns": session.turns,
        "scamDetected": session.scam_detected,
        "scamType": session.scam_type,
        "intelligence": session.intelligence,
        "isComplete": session.is_complete
    }
