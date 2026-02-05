# Intelligence Extractor - Extracts scammer information
import re
from typing import List, Dict, Any
from dataclasses import dataclass


@dataclass
class ExtractedIntel:
    """Single piece of extracted intelligence."""
    type: str  # upi, phone, link
    value: str
    confidence: float
    source_turn: int
    context: str  # surrounding text


def extract_upi_ids(text: str) -> List[str]:
    """Extract UPI IDs from text."""
    # Pattern: something@something (UPI format)
    pattern = r"\b[\w.-]+@[a-zA-Z]{2,}\b"
    matches = re.findall(pattern, text)
    # Filter out email-like patterns
    upi_suffixes = ['upi', 'paytm', 'ybl', 'okhdfcbank', 'okaxis', 'okicici', 'apl', 'ibl']
    return [m for m in matches if any(m.lower().endswith(s) for s in upi_suffixes) or '@' in m]


def extract_phone_numbers(text: str) -> List[str]:
    """Extract Indian phone numbers from text."""
    # 10 digits starting with 6-9
    pattern = r"\b[6-9]\d{9}\b"
    return re.findall(pattern, text)


def extract_links(text: str) -> List[str]:
    """Extract URLs from text."""
    pattern = r"https?://[^\s<>\"{}|\\^`\[\]]+"
    return re.findall(pattern, text)


def extract_bank_accounts(text: str) -> List[str]:
    """Extract potential bank account numbers."""
    # 9-18 digit numbers (common account number length)
    pattern = r"\b\d{9,18}\b"
    matches = re.findall(pattern, text)
    # Filter out phone numbers
    return [m for m in matches if not (len(m) == 10 and m[0] in '6789')]


def extract_ifsc_codes(text: str) -> List[str]:
    """Extract IFSC codes."""
    # IFSC: 4 letters + 0 + 6 alphanumeric
    pattern = r"\b[A-Z]{4}0[A-Z0-9]{6}\b"
    return re.findall(pattern, text, re.IGNORECASE)


def extract_all(text: str, turn_number: int) -> Dict[str, List[ExtractedIntel]]:
    """
    Extract all intelligence from a message.
    Returns structured intel with metadata.
    """
    result = {
        "upiIds": [],
        "phoneNumbers": [],
        "links": [],
        "bankAccounts": [],
        "ifscCodes": []
    }
    
    # Get context (first 50 chars around match)
    def get_context(value: str, full_text: str) -> str:
        idx = full_text.lower().find(value.lower())
        if idx == -1:
            return full_text[:50]
        start = max(0, idx - 20)
        end = min(len(full_text), idx + len(value) + 30)
        return full_text[start:end]
    
    # Extract each type
    for upi in extract_upi_ids(text):
        result["upiIds"].append(ExtractedIntel(
            type="upi",
            value=upi,
            confidence=0.9,  # High confidence for pattern match
            source_turn=turn_number,
            context=get_context(upi, text)
        ))
    
    for phone in extract_phone_numbers(text):
        result["phoneNumbers"].append(ExtractedIntel(
            type="phone",
            value=phone,
            confidence=0.85,
            source_turn=turn_number,
            context=get_context(phone, text)
        ))
    
    for link in extract_links(text):
        result["links"].append(ExtractedIntel(
            type="link",
            value=link,
            confidence=0.95,
            source_turn=turn_number,
            context=get_context(link, text)
        ))
    
    for account in extract_bank_accounts(text):
        result["bankAccounts"].append(ExtractedIntel(
            type="bank_account",
            value=account,
            confidence=0.7,  # Lower confidence, could be any number
            source_turn=turn_number,
            context=get_context(account, text)
        ))
    
    for ifsc in extract_ifsc_codes(text):
        result["ifscCodes"].append(ExtractedIntel(
            type="ifsc",
            value=ifsc,
            confidence=0.95,
            source_turn=turn_number,
            context=get_context(ifsc, text)
        ))
    
    return result


def count_intel(intel_dict: Dict) -> int:
    """Count total intelligence pieces extracted."""
    count = 0
    for key in ["upiIds", "phoneNumbers", "links", "bankAccounts", "ifscCodes"]:
        if key in intel_dict:
            count += len(intel_dict[key])
    return count
