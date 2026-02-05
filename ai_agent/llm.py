# LLM Language Wrapper - ONLY for phrasing, NOT for decisions
# LLM converts intent → natural language response
import os
from typing import Optional
from ai_agent.persona import Persona, get_system_prompt, validate_response, get_fallback_response


# LLM Configuration
LLM_CONFIG = {
    "temperature": 0.3,      # Low temperature for consistency
    "max_tokens": 50,        # Short responses only
    "model": "gpt-3.5-turbo" # Can be changed
}


def phrase_with_llm(
    intent: str,
    persona: Persona,
    scammer_message: str
) -> str:
    """
    Use LLM to phrase the intent naturally.
    
    CRITICAL: LLM only converts intent to natural language.
    It does NOT decide what to say - that's done by agent.py
    
    If LLM is unavailable or fails, returns safe fallback.
    """
    try:
        # Check if OpenAI is available
        import openai
        
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            # No API key, use fallback
            return get_fallback_response(intent.split()[0].upper() if intent else "CONFUSED")
        
        client = openai.OpenAI(api_key=api_key)
        
        system_prompt = get_system_prompt(persona)
        user_prompt = f"""The caller said: "{scammer_message}"

Your intent: {intent}

Respond naturally as this persona would. One sentence only, under 25 words."""
        
        response = client.chat.completions.create(
            model=LLM_CONFIG["model"],
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=LLM_CONFIG["temperature"],
            max_tokens=LLM_CONFIG["max_tokens"]
        )
        
        reply = response.choices[0].message.content.strip()
        
        # Validate response doesn't contain forbidden words
        if validate_response(reply, persona):
            return reply
        else:
            # LLM used forbidden word, use fallback
            return get_fallback_response(intent.split()[0].upper() if intent else "CONFUSED")
            
    except ImportError:
        # OpenAI not installed
        return get_fallback_response("CONFUSED")
    except Exception as e:
        # Any error, use fallback
        print(f"LLM Error: {e}")
        return get_fallback_response("CONFUSED")


def phrase_reply(
    intent: str,
    state_name: str,
    persona: Persona,
    scammer_message: str,
    use_llm: bool = False
) -> str:
    """
    Main function to generate agent reply.
    
    Args:
        intent: What the agent wants to communicate
        state_name: Current agent state (for fallback)
        persona: Agent persona
        scammer_message: The scammer's last message
        use_llm: Whether to use LLM (default False for safety)
    
    Returns:
        Natural language response
    """
    if use_llm:
        return phrase_with_llm(intent, persona, scammer_message)
    else:
        # Use deterministic fallback responses
        return get_fallback_response(state_name)


# Deterministic reply templates (no LLM needed)
STATE_REPLIES = {
    "INIT": [
        "Sir, what is happening? I don't understand.",
        "What do you mean? Is there a problem?",
    ],
    "CONFUSED": [
        "But why is my account blocked? I didn't do anything wrong.",
        "Sir, please explain. What mistake have I made?",
        "I don't understand. Can you tell me more?",
    ],
    "TRUSTING": [
        "Okay sir, please tell me what I need to do.",
        "I am very worried. Please help me fix this.",
        "What steps should I take? Please guide me.",
    ],
    "COMPLIANT": [
        "Okay, I will do as you say. Where should I send the money?",
        "Please give me the details. I want to fix this quickly.",
        "I am ready to pay. What is the UPI ID?",
    ],
    "EXTRACTION": [
        "Can you share the payment details again? I want to be sure.",
        "What is your phone number so I can confirm?",
        "Is there an official link I should visit?",
    ],
    "EXIT": [
        "Okay sir, I will do it in some time. Thank you.",
        "Let me think about this. I will call you back.",
        "Thank you for informing me. I need to go now.",
    ]
}


def get_deterministic_reply(state_name: str, turn: int) -> str:
    """
    Get a deterministic reply without using LLM.
    Cycles through templates based on turn count.
    """
    replies = STATE_REPLIES.get(state_name, STATE_REPLIES["CONFUSED"])
    index = turn % len(replies)
    return replies[index]
