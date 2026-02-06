# HONEY-POT

A State-Driven Agentic Honeypot API that simulates a vulnerable victim persona to engage with scammers, extract intelligence, and profile malicious behavior.

## Overview

This project implements an AI-powered honeypot system designed to:
- **Detect scam attempts** using keyword analysis and pattern matching
- **Engage scammers** with a realistic victim persona (confused, non-tech-savvy individual)
- **Extract intelligence** such as UPI IDs, phone numbers, and malicious links
- **Profile attacker behavior** through conversation analysis
- **Maintain engagement** using a state machine to control conversation flow

## Architecture

```
honey-pot_api/          # Main API entry point
├── main.py             # FastAPI app, LLM integration, state machine

ai_agent/               # AI Agent components
├── agent.py            # Intent generation logic
├── state_machine.py    # Agent state definitions
├── extractor.py        # Intelligence extraction
├── profiler.py         # Behavior profiling
├── persona.py          # Victim persona management
├── llm.py              # LLM configuration
└── intelligence_model.py

services/               # Core services
├── server.py           # FastAPI app factory
├── auth.py             # API key authentication
├── detector.py         # Scam detection engine
├── session.py          # Session management
└── callback.py         # GUVI callback integration
```

## Agent State Machine

The honeypot uses a 6-state conversation flow:

| State | Description |
|-------|-------------|
| `INIT` | Initial contact, express confusion |
| `CONFUSED` | Show worry, ask clarifying questions |
| `TRUSTING` | Begin cooperating, ask for guidance |
| `COMPLIANT` | Agree to instructions, request payment details |
| `EXTRACTION` | Actively probe for UPI/phone/links |
| `EXIT` | Gracefully end conversation |

## Features

### Scam Detection Engine
Analyzes messages for scam indicators across categories:
- **Urgency**: "immediately", "urgent", "now"
- **Threats**: "blocked", "legal action", "arrest"
- **Financial**: "UPI", "transfer", "payment"
- **Authority impersonation**: "RBI", "government", "income tax"
- **Verification requests**: "KYC", "OTP", "Aadhar"

### LLM Integration
Uses GPT-3.5-turbo with cost-optimized settings:
- Low temperature (0.3) for consistent responses
- Max 40 tokens per response
- Safety filters to prevent breaking character

### Intelligence Extraction
Automatically captures:
- UPI IDs
- Phone numbers
- Malicious URLs
- Bank account details

## Installation

```bash
# Clone the repository
git clone https://github.com/sushant-bot/HONEY-POT.git
cd HONEY-POT

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Add your OPENAI_API_KEY to .env
```

## Configuration

Create a `.env` file with:

```env
OPENAI_API_KEY=your_openai_api_key_here
```

## Usage

### Start the API Server

```bash
cd honey-pot_api
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/chat` | Send a message to the honeypot |
| GET | `/session/{id}` | Get session intelligence |
| GET | `/health` | Health check |

## Requirements

- Python 3.8+
- FastAPI
- OpenAI API key (for LLM responses)
- uvicorn

See [requirements.txt](requirements.txt) for full dependencies.

## How It Works

1. **Scammer sends message** → Scam detection engine analyzes content
2. **State machine evaluates** → Determines appropriate response state
3. **Intent generated** → Decides WHAT to communicate (deterministic)
4. **LLM generates response** → Creates natural language reply
5. **Intelligence extracted** → Captures any revealed scammer data
6. **Behavior profiled** → Updates attacker profile

## Safety Features

- Forbidden word filtering prevents the bot from revealing its nature
- Persona consistency maintained across all responses
- No real personal information is ever shared
- All extracted intelligence is logged securely

## License

MIT License

## Acknowledgments

Built for the GUVI Hackathon.
