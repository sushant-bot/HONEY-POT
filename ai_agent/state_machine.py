# Agent State Machine - Controls agent behavior flow
from enum import Enum
from typing import Optional


class AgentState(Enum):
    """Agent states in the honeypot conversation."""
    INIT = "INIT"              # Initial state, just received first scam message
    CONFUSED = "CONFUSED"       # Pretending to be confused about the situation
    TRUSTING = "TRUSTING"       # Starting to trust the scammer
    COMPLIANT = "COMPLIANT"     # Agreeing to follow instructions
    EXTRACTION = "EXTRACTION"   # Actively trying to extract intelligence
    EXIT = "EXIT"               # Ending the conversation ethically


# State transition rules
STATE_TRANSITIONS = {
    AgentState.INIT: [AgentState.CONFUSED],
    AgentState.CONFUSED: [AgentState.TRUSTING, AgentState.EXIT],
    AgentState.TRUSTING: [AgentState.COMPLIANT, AgentState.EXIT],
    AgentState.COMPLIANT: [AgentState.EXTRACTION, AgentState.EXIT],
    AgentState.EXTRACTION: [AgentState.EXTRACTION, AgentState.EXIT],
    AgentState.EXIT: []  # Terminal state
}


def get_next_state(
    current_state: AgentState,
    turn_count: int,
    has_payment_request: bool,
    intelligence_count: int,
    max_turns: int = 10
) -> AgentState:
    """
    Determine next agent state based on conversation progress.
    This is DETERMINISTIC - no AI involved.
    """
    # Exit conditions (ethical limits)
    if turn_count >= max_turns:
        return AgentState.EXIT
    
    if intelligence_count >= 3:
        # We have enough intel, start wrapping up
        if current_state == AgentState.EXTRACTION:
            return AgentState.EXIT
    
    # Normal state progression
    if current_state == AgentState.INIT:
        return AgentState.CONFUSED
    
    elif current_state == AgentState.CONFUSED:
        if turn_count >= 2:
            return AgentState.TRUSTING
        return AgentState.CONFUSED
    
    elif current_state == AgentState.TRUSTING:
        if has_payment_request or turn_count >= 4:
            return AgentState.COMPLIANT
        return AgentState.TRUSTING
    
    elif current_state == AgentState.COMPLIANT:
        if turn_count >= 5:
            return AgentState.EXTRACTION
        return AgentState.COMPLIANT
    
    elif current_state == AgentState.EXTRACTION:
        if intelligence_count >= 2 or turn_count >= 8:
            return AgentState.EXIT
        return AgentState.EXTRACTION
    
    return current_state


def is_exit_state(state: AgentState) -> bool:
    """Check if the agent should exit."""
    return state == AgentState.EXIT
