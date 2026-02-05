# API key authentication helper
from fastapi import Header, HTTPException, status

# Hardcoded API key for the hackathon
API_KEY = "SLEPPYcoder2026"


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
