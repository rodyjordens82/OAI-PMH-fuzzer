import os
import re
import logging
from collections import Counter

# Configure logging
LOGGER = logging.getLogger("oai_sanitizer")
LOGGER.setLevel(logging.DEBUG)

# File handler for blocked requests
blocked_log_handler = logging.FileHandler("/app/logs/blocked_requests.log")
blocked_log_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
blocked_log_handler.setFormatter(blocked_log_formatter)
LOGGER.addHandler(blocked_log_handler)

# Constants
PAYLOADS_DIR = os.getenv("PAYLOADS_DIR", "payloads")

# Statistics counters
blocked_request_counter = Counter()
forwarded_request_counter = Counter()
classification_counters = {
    "true_positive": 0,
    "false_positive": 0,
    "true_negative": 0,
    "false_negative": 0,
}

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
            classification_counters["true_positive"] += 1
            continue

        if key == "verb" and value not in valid_verbs:
            LOGGER.warning(f"Blocked invalid verb: {value}")
            blocked_request_counter["Invalid Verb"] += 1
            block_request = True
            classification_counters["true_positive"] += 1
            continue

        if re.search(r'[;&|`<>]', value):
            LOGGER.warning(f"Blocked command injection in {key}: {value}")
            blocked_request_counter["Command Injection"] += 1
            block_request = True
            classification_counters["true_positive"] += 1
            continue

        if "SYSTEM" in value.upper() or "DTD" in value.upper():
            LOGGER.warning(f"Blocked DTD injection in {key}: {value}")
            blocked_request_counter["DTD Injection"] += 1
            block_request = True
            classification_counters["true_positive"] += 1
            continue

        sanitized[key] = value

    if not block_request:
        forwarded_request_counter["Forwarded Requests"] += 1
        classification_counters["true_negative"] += 1
        LOGGER.info(f"Request sanitized and valid: {sanitized}")
    else:
        classification_counters["false_positive"] += 1

    return sanitized, block_request

def log_blocked_requests():
    """Logs the total number of blocked requests due to malicious content."""
    for reason, count in blocked_request_counter.items():
        LOGGER.info(f"Blocked {count} requests due to: {reason}")

def log_forwarded_requests():
    """Logs the total number of forwarded requests."""
    for reason, count in forwarded_request_counter.items():
        LOGGER.info(f"Forwarded {count} requests.")

def calculate_efficiency_metrics():
    """Calculate precision, recall, and accuracy."""
    tp = classification_counters["true_positive"]
    fp = classification_counters["false_positive"]
    tn = classification_counters["true_negative"]
    fn = classification_counters["false_negative"]

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0

    LOGGER.info(f"Precision: {precision:.2f}")
    LOGGER.info(f"Recall: {recall:.2f}")
    LOGGER.info(f"Accuracy: {accuracy:.2f}")
