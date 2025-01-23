import os
import re
import logging
from collections import Counter

# Configure logging
LOGGER = logging.getLogger("oai_sanitizer")
LOGGER.setLevel(logging.DEBUG)
file_handler = logging.FileHandler("oai_sanitizer.log")
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)
LOGGER.addHandler(file_handler)

# Constants
PAYLOADS_DIR = os.getenv("PAYLOADS_DIR", "payloads")

# Statistics counters
blocked_request_counter = Counter()

def load_payloads():
    """Loads payloads from all text files in the payloads directory."""
    payloads = []
    if not os.path.exists(PAYLOADS_DIR):
        LOGGER.warning(f"Payload directory {PAYLOADS_DIR} does not exist.")
        return payloads
    for filename in os.listdir(PAYLOADS_DIR):
        filepath = os.path.join(PAYLOADS_DIR, filename)
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                payloads.extend(line.strip() for line in file if line.strip())
        except (UnicodeDecodeError, FileNotFoundError) as e:
            LOGGER.error(f"Error loading {filename}: {e}")
    return payloads

def sanitize_params(params):
    """
    Sanitizes the OAI-PMH request parameters.
    Blocks or transforms any malicious input such as DTD injections or command injections.
    """
    sanitized = {}
    valid_verbs = {
        "Identify",
        "ListMetadataFormats",
        "ListSets",
        "ListIdentifiers",
        "ListRecords",
        "GetRecord"
    }
    valid_params = {"verb", "identifier", "metadataPrefix", "from", "until", "set", "resumptionToken"}

    block_request = False

    for key, value in params.items():
        if key not in valid_params:
            LOGGER.warning(f"Blocked invalid parameter: {key}")
            blocked_request_counter["Invalid Parameter"] += 1
            block_request = True
            continue

        if key == "verb" and value not in valid_verbs:
            LOGGER.warning(f"Blocked invalid verb: {value}")
            blocked_request_counter["Invalid Verb"] += 1
            block_request = True
            continue

        if re.search(r'[;&|`<>]', value):
            LOGGER.warning(f"Blocked command injection in {key}: {value}")
            blocked_request_counter["Command Injection"] += 1
            block_request = True
            continue

        if "SYSTEM" in value.upper() or "DTD" in value.upper():
            LOGGER.warning(f"Blocked DTD injection in {key}: {value}")
            blocked_request_counter["DTD Injection"] += 1
            block_request = True
            continue

        sanitized[key] = value

    return sanitized, block_request

def log_blocked_requests():
    """Logs the total number of blocked requests due to malicious content."""
    for reason, count in blocked_request_counter.items():
        LOGGER.info(f"Blocked {count} requests due to: {reason}")
