from fastapi import FastAPI, HTTPException
from typing import Dict
import httpx
from sanitizer_logic import sanitize_params, load_payloads, log_blocked_requests, calculate_efficiency_metrics
import os
import logging

# Configure general logging for the application
LOGGER = logging.getLogger("oai_sanitizer")
LOGGER.setLevel(logging.INFO)

# Log to console
console_handler = logging.StreamHandler()
console_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
console_handler.setFormatter(console_formatter)
LOGGER.addHandler(console_handler)

# Log forwarded requests to a separate file
forwarded_log_handler = logging.FileHandler("/app/logs/forwarded_requests.log")
forwarded_log_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
forwarded_log_handler.setFormatter(forwarded_log_formatter)
LOGGER.addHandler(forwarded_log_handler)

# Load target OAI-PMH endpoint
TARGET_URL = os.getenv("TARGET_URL", "http://islandora.io/oai/request")

app = FastAPI()

@app.get("/")
async def health_check():
    """Health check endpoint."""
    return {"status": "Sanitizer is running"}

@app.post("/sanitize")
async def sanitize(params: Dict[str, str]):
    sanitized_params, block_request = sanitize_params(params)

    if block_request:
        LOGGER.warning(f"Blocked request: {params}")
        raise HTTPException(status_code=403, detail="Request blocked due to malicious content.")

    LOGGER.info(f"Sanitized Params: {sanitized_params}")

    try:
        async with httpx.AsyncClient() as client:
            LOGGER.info(f"Forwarding to TARGET_URL: {TARGET_URL} with params: {sanitized_params}")
            response = await client.get(TARGET_URL, params=sanitized_params)
            LOGGER.info(f"Response from TARGET_URL: {response.status_code}, Body: {response.text[:200]}")

            return {
                "status_code": response.status_code,
                "content": response.text,
                "headers": dict(response.headers),
            }
    except httpx.RequestError as e:
        LOGGER.error(f"Error forwarding request to {TARGET_URL}: {e}")
        raise HTTPException(status_code=500, detail="Error forwarding request to the OAI-PMH endpoint.")

@app.on_event("startup")
async def startup_event():
    """Load external payloads during startup."""
    LOGGER.info("Starting up the sanitizer application")
    load_payloads()

@app.on_event("shutdown")
async def shutdown_event():
    """Log metrics and blocked requests before shutting down."""
    LOGGER.info("Shutting down the sanitizer application")
    log_blocked_requests()
    calculate_efficiency_metrics()
