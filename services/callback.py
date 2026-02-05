# GUVI Callback Service - Final report submission
import os
import httpx
from typing import Dict, Any, Optional
from datetime import datetime


# GUVI Callback Configuration
GUVI_CALLBACK_URL = os.environ.get("GUVI_CALLBACK_URL", "https://guvi-callback.example.com/report")
GUVI_API_KEY = os.environ.get("GUVI_API_KEY", "")


async def send_final_callback(
    session_id: str,
    session_data: Dict[str, Any],
    intelligence_report: Dict[str, Any],
    behavior_summary: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Send final callback to GUVI with complete session report.
    This is MANDATORY for scoring.
    """
    # Build the callback payload
    payload = {
        "timestamp": datetime.utcnow().isoformat(),
        "sessionId": session_id,
        "scamDetected": session_data.get("scam_detected", False),
        "scamType": session_data.get("scam_type", "UNKNOWN"),
        "conversationTurns": session_data.get("turns", 0),
        "extractedIntelligence": intelligence_report.get("extractedIntelligence", []),
        "agentConfidence": intelligence_report.get("agentConfidence", 0.0),
        "behaviorProfile": behavior_summary,
        "crossSessionLinks": session_data.get("cross_session_links", {}),
        "exitReason": session_data.get("exit_reason", "max_turns_reached")
    }
    
    # For now, just log the callback (actual HTTP call when URL is configured)
    print("=" * 50)
    print("GUVI CALLBACK PAYLOAD:")
    print(payload)
    print("=" * 50)
    
    # If callback URL is configured, send it
    if GUVI_CALLBACK_URL and "example.com" not in GUVI_CALLBACK_URL:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    GUVI_CALLBACK_URL,
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "x-api-key": GUVI_API_KEY
                    },
                    timeout=10.0
                )
                return {
                    "sent": True,
                    "status_code": response.status_code,
                    "response": response.json() if response.status_code == 200 else None
                }
        except Exception as e:
            print(f"Callback error: {e}")
            return {"sent": False, "error": str(e)}
    
    return {"sent": False, "reason": "callback_url_not_configured", "payload": payload}


def build_callback_payload(
    session_id: str,
    scam_detected: bool,
    scam_type: str,
    turns: int,
    intelligence: Dict[str, list],
    agent_confidence: float,
    behavior_summary: Dict[str, Any],
    cross_links: Dict[str, Dict],
    exit_reason: str = "completed"
) -> Dict[str, Any]:
    """
    Build the callback payload structure.
    Use this for synchronous contexts.
    """
    # Format intelligence
    formatted_intel = []
    for intel_type in ["upiIds", "phoneNumbers", "links", "bankAccounts", "ifscCodes"]:
        for item in intelligence.get(intel_type, []):
            if isinstance(item, dict):
                formatted_intel.append({
                    "type": intel_type,
                    "value": item.get("value", str(item)),
                    "confidence": item.get("confidence", 0.8)
                })
            elif isinstance(item, str):
                formatted_intel.append({
                    "type": intel_type,
                    "value": item,
                    "confidence": 0.8
                })
    
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "sessionId": session_id,
        "scamDetected": scam_detected,
        "scamType": scam_type,
        "conversationTurns": turns,
        "extractedIntelligence": formatted_intel,
        "agentConfidence": agent_confidence,
        "behaviorProfile": behavior_summary,
        "crossSessionLinks": {k: v for k, v in cross_links.items() if v},
        "exitReason": exit_reason
    }


def log_callback(payload: Dict[str, Any]) -> None:
    """Log callback payload for debugging."""
    print("\n" + "=" * 60)
    print("📡 FINAL GUVI CALLBACK")
    print("=" * 60)
    print(f"Session ID: {payload.get('sessionId')}")
    print(f"Scam Detected: {payload.get('scamDetected')}")
    print(f"Scam Type: {payload.get('scamType')}")
    print(f"Turns: {payload.get('conversationTurns')}")
    print(f"Agent Confidence: {payload.get('agentConfidence')}")
    print(f"Intelligence Items: {len(payload.get('extractedIntelligence', []))}")
    print(f"Exit Reason: {payload.get('exitReason')}")
    print("=" * 60 + "\n")
