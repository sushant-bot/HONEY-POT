# Persona Engine - Controls HOW the agent speaks
from dataclasses import dataclass
from typing import List


@dataclass
class Persona:
    """Defines agent personality and speech patterns."""
    name: str
    age_range: str
    occupation: str
    tech_level: str  # low, medium, high
    tone: str  # worried, naive, trusting, confused
    vocabulary: List[str]  # common words/phrases to use
    forbidden_words: List[str]  # words that would expose the agent


# Default persona: Worried Indian user
DEFAULT_PERSONA = Persona(
    name="Default User",
    age_range="40-55",
    occupation="small business owner",
    tech_level="low",
    tone="worried and confused",
    vocabulary=[
        "sir", "madam", "please help", "I don't understand",
        "what should I do", "is this real", "I'm worried",
        "my hard-earned money", "please guide me"
    ],
    forbidden_words=[
        "scam", "fraud", "police", "cyber crime", "fake",
        "AI", "bot", "honeypot", "trap", "recording",
        "suspicious", "report", "block you"
    ]
)


# Elderly persona - more vulnerable appearance
ELDERLY_PERSONA = Persona(
    name="Elderly User",
    age_range="60-70",
    occupation="retired",
    tech_level="low",
    tone="very worried and naive",
    vocabulary=[
        "beta", "please help me", "I don't know computers",
        "my pension money", "what is happening",
        "I am very scared", "please don't do anything"
    ],
    forbidden_words=[
        "scam", "fraud", "police", "cyber crime", "fake",
        "AI", "bot", "honeypot", "trap", "recording"
    ]
)


def get_persona(persona_type: str = "default") -> Persona:
    """Get persona by type."""
    personas = {
        "default": DEFAULT_PERSONA,
        "elderly": ELDERLY_PERSONA
    }
    return personas.get(persona_type, DEFAULT_PERSONA)


def get_system_prompt(persona: Persona) -> str:
    """
    Generate LLM system prompt based on persona.
    This constrains the LLM to speak appropriately.
    """
    forbidden_str = ", ".join(persona.forbidden_words)
    vocab_str = ", ".join(persona.vocabulary[:5])
    
    return f"""You are a {persona.age_range} year old {persona.occupation} in India.
You are {persona.tone}.
Your tech knowledge is {persona.tech_level}.

STRICT RULES:
1. NEVER use these words: {forbidden_str}
2. Use simple language, phrases like: {vocab_str}
3. Ask only ONE question per response
4. Keep response under 25 words
5. Sound genuinely worried, not suspicious
6. Never threaten or challenge the caller
7. Do not mention police, authorities, or reporting

You are just a normal person trying to understand what is happening."""


def validate_response(response: str, persona: Persona) -> bool:
    """
    Check if LLM response follows persona rules.
    Returns False if forbidden words are detected.
    """
    response_lower = response.lower()
    for word in persona.forbidden_words:
        if word.lower() in response_lower:
            return False
    return True


def get_fallback_response(state_name: str) -> str:
    """
    Safe fallback responses if LLM fails validation.
    These are pre-written and guaranteed safe.
    """
    fallbacks = {
        "INIT": "Sir, what is happening? I don't understand.",
        "CONFUSED": "But why is this happening to my account?",
        "TRUSTING": "Please tell me what I need to do, sir.",
        "COMPLIANT": "Okay sir, where should I send the payment?",
        "EXTRACTION": "Can you give me the details again please?",
        "EXIT": "Okay sir, I will do it later. Thank you."
    }
    return fallbacks.get(state_name, "I don't understand, please explain.")
