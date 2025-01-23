from fastapi import FastAPI, HTTPException, Query
from typing import Dict
from sanitizer_logic import sanitize_params, load_payloads, log_blocked_requests

app = FastAPI()

@app.get("/")
async def health_check():
    """Health check endpoint."""
    return {"status": "Sanitizer is running"}

@app.post("/sanitize")
async def sanitize(params: Dict[str, str]):
    """
    Endpoint to sanitize OAI-PMH request parameters.
    """
    sanitized_params, block_request = sanitize_params(params)
    if block_request:
        raise HTTPException(status_code=403, detail="Request blocked due to malicious content.")
    return {"sanitized": sanitized_params}

@app.on_event("startup")
async def startup_event():
    """Load external payloads during startup."""
    load_payloads()

@app.on_event("shutdown")
async def shutdown_event():
    """Log blocked requests before shutting down."""
    log_blocked_requests()
