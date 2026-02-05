# Agent Intent Logic - Decides WHAT to say (not HOW)
from ai_agent.state_machine import AgentState


# Intent templates based on state
STATE_INTENTS = {
    AgentState.INIT: [
        "express confusion about the situation",
        "ask why this is happening"
    ],
    AgentState.CONFUSED: [
        "ask why the account is blocked",
        "express worry about losing money",
        "ask what mistake was made"
    ],
    AgentState.TRUSTING: [
        "ask what steps are needed to fix this",
        "express willingness to cooperate",
        "ask for clarification on the process"
    ],
    AgentState.COMPLIANT: [
        "agree to follow the instructions",
        "ask where to send the payment",
        "ask for account or UPI details"
    ],
    AgentState.EXTRACTION: [
        "ask for payment details again",
        "ask for contact number for confirmation",
        "request official documentation"
    ],
    AgentState.EXIT: [
        "politely thank and end conversation",
        "say you need time to think",
        "mention you will do it later"
    ]
}


def generate_intent(state: AgentState, turn_count: int) -> str:
    """
    Generate intent based on current state.
    Intent is WHAT the agent wants to communicate.
    This is DETERMINISTIC - selected by code, not AI.
    """
    intents = STATE_INTENTS.get(state, STATE_INTENTS[AgentState.CONFUSED])
    
    # Cycle through intents based on turn count
    index = turn_count % len(intents)
    return intents[index]


def should_request_intel(state: AgentState, intel_count: int) -> bool:
    """
    Determine if agent should actively request intelligence.
    Only in COMPLIANT or EXTRACTION states.
    """
    if state in [AgentState.COMPLIANT, AgentState.EXTRACTION]:
        return intel_count < 3
    return False


def get_probing_intent(intel_type: str) -> str:
    """
    Get specific intent to probe for missing intelligence.
    """
    probes = {
        "upi": "ask where to send the payment",
        "phone": "ask for a contact number to confirm",
        "link": "ask for official website or form link"
    }
    return probes.get(intel_type, "ask for more details")
