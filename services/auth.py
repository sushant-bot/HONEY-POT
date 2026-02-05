# API key authentication helper
from fastapi import Header, HTTPException, status
import os
from dotenv import load_dotenv

# Load environment variables
env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
load_dotenv(env_path)

# Get API key from environment variable (NEVER hardcode in production!)
API_KEY = os.getenv("API_KEY")

if not API_KEY:
    print("⚠️  WARNING: API_KEY not found in .env file!")


def api_key_auth(x_api_key: str = Header(None)) -> str:
    """Validate the API key sent in the request headers."""
    if not API_KEY:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server misconfigured: API_KEY not set",
        )
    
    if x_api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API Key",
        )
    
    if x_api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key",
        )

    # Return the key so the dependency succeeds
    return x_api_key
