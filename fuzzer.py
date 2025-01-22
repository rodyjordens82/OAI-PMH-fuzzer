# During the development of the artifacts, generative AI was used
# to refine the code and generate comments in the code with explanations.
# The OpenAI models ChatGPT4o and 01 were utilized for this purpose.

import random
import string
import httpx
import logging
import os
import threading
from datetime import datetime
from collections import Counter
import statistics
import uuid

# Configure logging
logging.basicConfig(
    filename='oai_pmh_fuzzer.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# Status code logging
status_code_log = 'oai_pmh_status_codes.log'
with open(status_code_log, 'w') as f:
    f.write('uuid,timestamp,http_status_code,request_url,response_time,http_version\n')

# Server information logging
server_info_log = 'oai_pmh_server_info.log'
with open(server_info_log, 'w') as f:
    f.write('uuid,timestamp,http_status_code,request_url,response_time,http_version,headers\n')

# OAI-PMH endpoint
#OAI_PMH_URL = "https://tnov6-oai.vakliteratuur.info/OaiPmh" #use for just fuzzing x-ref
#OAI_PMH_URL = "http://localhost:8080/server/oai/request" #use for just fuzzing dspace
#OAI_PMH_URL = "http://islandora.io/oai/request" #use for just fuzzing islandora
OAI_PMH_URL = "http://localhost:8090/oai/request" #use in combination with sanitizer

# OAI-PMH verbs
OAI_PMH_VERBS = ["Identify", "ListMetadataFormats", "ListSets", "ListIdentifiers", "ListRecords", "GetRecord"]

# Payloads directory
PAYLOADS_DIR = "payloads"

# Counter for HTTP status codes and versions
status_code_counter = Counter()
http_version_counter = Counter()

# Response times storage
response_times = []

def load_payloads_by_file():
    """Loads payloads grouped by file from the payloads directory."""
    payloads = {}
    if os.path.exists(PAYLOADS_DIR):
        for filename in os.listdir(PAYLOADS_DIR):
            filepath = os.path.join(PAYLOADS_DIR, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as file:
                    payloads[filename] = [line.strip() for line in file if line.strip()]
            except UnicodeDecodeError as e:
                logging.error(f"Failed to decode {filename}: {e}")
    return payloads

# Load external payloads
PAYLOAD_FILES = load_payloads_by_file()

def generate_fuzzed_params(verb, payload):
    params = {"verb": verb}
    if verb == "GetRecord":
        params["identifier"] = payload
        params["metadataPrefix"] = random.choice(["oai_dc", "marc"])
    elif verb in ["ListIdentifiers", "ListRecords"]:
        params["metadataPrefix"] = random.choice(["oai_dc", "marc"])
        if random.choice([True, False]):
            params["from"] = payload
        if random.choice([True, False]):
            params["until"] = payload
        if random.choice([True, False]):
            params["set"] = payload
    elif verb == "ListMetadataFormats":
        if random.choice([True, False]):
            params["identifier"] = payload
    elif verb == "ListSets":
        if random.choice([True, False]):
            params["resumptionToken"] = payload
    else:
        params["verb"] = payload
    return params

def log_status_code(request_uuid, status_code, url, response_time, http_version):
    """Logs HTTP status codes to a separate file."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(status_code_log, 'a') as f:
        f.write(f"{request_uuid},{timestamp},{status_code},{url},{response_time:.2f} ms,{http_version}\n")
    status_code_counter[status_code] += 1
    http_version_counter[http_version] += 1
    response_times.append(response_time)

def log_server_info(request_uuid, url, headers, status_code, response_time, http_version):
    """Logs server information to a separate file."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    headers_str = '; '.join([f"{key}: {value}" for key, value in headers.items()])
    with open(server_info_log, 'a') as f:
        f.write(f"{request_uuid},{timestamp},{status_code},{url},{response_time:.2f} ms,{http_version},{headers_str}\n")

def summarize_status_codes():
    """Summarizes the status codes and writes to the status code log."""
    with open(status_code_log, 'a') as f:
        total_requests = sum(status_code_counter.values())
        f.write("\nSummary:\n")
        f.write(f"Total requests: {total_requests}\n")
        f.write(f"Median response time: {statistics.median(response_times):.2f} ms\n")
        f.write(f"HTTP/1.1 requests: {http_version_counter['HTTP/1.1']}x\n")
        for status_code, count in status_code_counter.items():
            f.write(f"{status_code}: {count}x\n")

def fuzz_oai_pmh_with_payloads():
    headers = {"Content-Type": "application/xml", "Accept": "application/xml"}

    for filename, payloads in PAYLOAD_FILES.items():
        logging.info(f"Fuzzing with payloads from: {filename}")
        for payload in payloads:
            for verb in OAI_PMH_VERBS:
                request_uuid = str(uuid.uuid4())
                params = generate_fuzzed_params(verb, payload)

                # Enforce HTTP/1.1
                transport = httpx.HTTPTransport(http1=True, http2=False)

                with httpx.Client(transport=transport) as client:
                    try:
                        start_time = datetime.now()
                        response = client.get(OAI_PMH_URL, params=params, headers=headers)
                        end_time = datetime.now()

                        response_time = (end_time - start_time).total_seconds() * 1000  # Convert to milliseconds

                        log_status_code(request_uuid, response.status_code, response.url, response_time, "HTTP/1.1")
                        log_server_info(request_uuid, response.url, response.headers, response.status_code, response_time, "HTTP/1.1")

                        print(f"[UUID: {request_uuid}] File: {filename}, Verb: {verb}, Response Code: {response.status_code}, Time: {response_time:.2f} ms")
                    except httpx.RequestError as e:
                        logging.error(f"Error: {e}")

if __name__ == "__main__":
    logging.info("Starting OAI-PMH fuzzing session with payload files.")
    fuzz_oai_pmh_with_payloads()
    summarize_status_codes()
    logging.info("Fuzzing session completed.")
