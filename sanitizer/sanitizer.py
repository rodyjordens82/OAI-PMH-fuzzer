from fastapi import FastAPI, HTTPException, Query
from typing import Dict
import httpx
from sanitizer_logic import sanitize_params, load_payloads, log_blocked_requests
import os
import logging

# Configure logging
LOGGER = logging.getLogger("oai_sanitizer")

# Load target OAI-PMH endpoint
TARGET_URL = os.getenv("TARGET_URL", "http://localhost:8080/server/oai")  # Replace with your endpoint

app = FastAPI()

@app.get("/")
async def health_check():
    """Health check endpoint."""
    return {"status": "Sanitizer is running"}

@app.post("/sanitize")
async def sanitize(params: Dict[str, str]):
    """
    Endpoint to sanitize OAI-PMH request parameters.
    Valid requests are forwarded to the target OAI-PMH endpoint.
    """
    sanitized_params, block_request = sanitize_params(params)

    if block_request:
        LOGGER.warning(f"Blocked request: {params}")
        raise HTTPException(status_code=403, detail="Request blocked due to malicious content.")

    # Forward valid requests to the OAI-PMH endpoint
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(TARGET_URL, params=sanitized_params)
            LOGGER.info(f"Forwarded request to {TARGET_URL} with sanitized params: {sanitized_params}")
            return {
                "status_code": response.status_code,
                "content": response.text,
                "headers": dict(response.headers),
            }
    except httpx.RequestError as e:
        LOGGER.error(f"Error forwarding request: {e}")
        raise HTTPException(status_code=500, detail="Error forwarding request to the OAI-PMH endpoint.")

@app.on_event("startup")
async def startup_event():
    """Load external payloads during startup."""
    load_payloads()

@app.on_event("shutdown")
async def shutdown_event():
    """Log blocked requests before shutting down."""
    log_blocked_requests()
