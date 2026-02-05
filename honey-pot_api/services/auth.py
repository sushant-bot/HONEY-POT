# API key authentication helper
import os
from fastapi import Header, HTTPException, status
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Hardcoded API key (fallback if env not set)
API_KEY = os.getenv("API_KEY", "honeypot_live_84xKp2M9TqZ6W3J1D7")


def api_key_auth(x_api_key: str = Header(None)) -> str:
    """Validate the API key sent in the request headers."""
    # If the key is missing, return 401
    if x_api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API Key",
        )
    
    # If the key is incorrect, return 401
    if x_api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key",
        )

    # Return the key so the dependency succeeds
    return x_api_key
