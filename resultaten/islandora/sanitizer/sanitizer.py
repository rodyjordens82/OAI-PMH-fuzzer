import random
import string
import logging
import os
import re
from datetime import datetime
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests
from requests.adapters import HTTPAdapter
import uuid

# Configure logging
LOGGER = logging.getLogger("oai_sanitizer")
LOGGER.setLevel(logging.DEBUG)

file_handler = logging.FileHandler("oai_sanitizer.log")
file_handler.setLevel(logging.DEBUG)

formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)

LOGGER.addHandler(file_handler)

# Constants
#DEFAULT_TARGET_URL = os.getenv("TARGET_URL", "https://tnov6-oai.vakliteratuur.info/OaiPmh") # x-ref
DEFAULT_TARGET_URL = os.getenv("TARGET_URL", "http://islandora.io/oai/request") # islandora
#DEFAULT_TARGET_URL = os.getenv("TARGET_URL", "http://localhost:8080/server/oai/request") # dspace
DEFAULT_PORT = int(os.getenv("SANITIZER_PORT", 8081))
PAYLOADS_DIR = os.getenv("PAYLOADS_DIR", "payloads")

# Statistics counters
status_code_counter = Counter()
response_times = []
blocked_request_counter = Counter()

# Load payloads from all files in the payloads directory
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

# Load external payloads
EXTERNAL_PAYLOADS = load_payloads()

# Sanitization
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

    # Flag to indicate if the request should be blocked
    block_request = False

    for key, value in params.items():
        # Check for invalid parameters
        if key not in valid_params:
            LOGGER.warning(f"Blocked invalid parameter: {key}")
            blocked_request_counter["Invalid Parameter"] += 1
            block_request = True
            continue

        # Check for invalid verbs
        if key == "verb" and value not in valid_verbs:
            LOGGER.warning(f"Blocked invalid verb: {value}")
            blocked_request_counter["Invalid Verb"] += 1
            block_request = True
            continue

        # Check for command injection patterns
        if re.search(r'[;&|`<>]', value):
            LOGGER.warning(f"Blocked command injection in {key}: {value}")
            blocked_request_counter["Command Injection"] += 1
            block_request = True
            continue

        # Check for DTD injection patterns
        if "SYSTEM" in value.upper() or "DTD" in value.upper():
            LOGGER.warning(f"Blocked DTD injection in {key}: {value}")
            blocked_request_counter["DTD Injection"] += 1
            block_request = True
            continue

        # If all checks pass, keep the parameter
        sanitized[key] = value

    return sanitized, block_request

# Function to log blocked request statistics
def log_blocked_requests():
    """
    Logs the total number of blocked requests due to malicious content.
    """
    for reason, count in blocked_request_counter.items():
        LOGGER.info(f"Blocked {count} requests due to: {reason}")

# HTTP Server to keep the sanitizer running
class SanitizerHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Log received request
        LOGGER.info(f"Received GET request: Path: {self.path} | Headers: {self.headers}")

        # Parse and sanitize parameters
        query_string = self.path.split('?')[-1] if '?' in self.path else ""
        params = dict(param.split('=') for param in query_string.split('&') if '=' in param)
        sanitized_params, block_request = sanitize_params(params)

        # Block the request if necessary
        if block_request:
            self.send_response(403)  # Forbidden
            self.end_headers()
            self.wfile.write(b"Request blocked due to malicious content.")
            LOGGER.warning(f"Blocked malicious request: {params}")
            return

        # Forward sanitized request to target endpoint
        try:
            # Use a session to enforce HTTP/1.1
            session = requests.Session()
            adapter = HTTPAdapter()
            session.mount("http://", adapter)
            session.mount("https://", adapter)

            response = session.get(DEFAULT_TARGET_URL, params=sanitized_params, headers={"Accept": "application/xml"})

            # Respond back to the client
            self.send_response(response.status_code)
            for key, value in response.headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(response.content)

            LOGGER.info(f"Forwarded request to {DEFAULT_TARGET_URL} with sanitized params: {sanitized_params}")
        except requests.RequestException as e:
            LOGGER.error(f"Error forwarding request: {e}")
            self.send_response(500)
            self.end_headers()

# Function to run the HTTP server
def run_sanitizer_server():
    server_address = ("localhost", DEFAULT_PORT)
    httpd = HTTPServer(server_address, SanitizerHTTPRequestHandler)
    LOGGER.info(f"Sanitizer is running on http://localhost:{DEFAULT_PORT}")
    try:
        httpd.serve_forever()  # Keeps the server running
    except KeyboardInterrupt:
        LOGGER.info("Sanitizer stopped manually.")
    except Exception as e:
        LOGGER.error(f"Error running the sanitizer: {e}")
    finally:
        # Log blocked request statistics before shutting down
        log_blocked_requests()
        httpd.server_close()
        LOGGER.info("Sanitizer server closed.")

if __name__ == "__main__":
    LOGGER.info("Starting sanitizer server.")
    run_sanitizer_server()
