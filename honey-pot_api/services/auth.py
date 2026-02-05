# API key authentication helper
import os
from fastapi import Header, HTTPException, status
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Load API key from environment variable
API_KEY = os.getenv("API_KEY")

if not API_KEY:
    raise RuntimeError("API_KEY environment variable is not set")


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
