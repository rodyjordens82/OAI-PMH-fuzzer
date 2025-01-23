# OAI-PMH Sanitizer

A lightweight FastAPI-based application for sanitizing OAI-PMH request parameters. This tool prevents malicious inputs, such as DTD injections or command injections, by blocking or transforming unsafe requests.

---

## Features
- Sanitizes OAI-PMH request parameters.
- Blocks invalid or unsafe requests.
- Logs malicious requests for review.
- Containerized with Docker for easy deployment.

---

## Directory Structure
```
sanitizer/
├── Dockerfile
├── requirements.txt
├── sanitizer.py
└── sanitizer_logic.py
```

---

## Requirements
- Python 3.9 or later
- Docker

---

## Setup

1. Clone this repository:
   ```bash
   git clone <repository-url>
   cd sanitizer
   ```

2. Install dependencies locally for development (optional):
   ```bash
   pip install -r requirements.txt
   ```

---

## Build and Run the Docker Container

### Build the Docker Image
To build the Docker image, run the following command:

```bash
docker build -t sanitizer .
```

### Run the Container
Start the container using the command below:

```bash
docker run -d -p 5000:5000 --name sanitizer-container sanitizer
```

---

## Testing the API

### Health Check
Verify the API is running by making a GET request to the health check endpoint:

```bash
curl http://localhost:5000/
```

Expected response:
```json
{
    "status": "Sanitizer is running"
}
```

### Sanitize Example
Test the sanitization functionality by sending a POST request with example data:

```bash
curl -X POST http://localhost:5000/sanitize -H "Content-Type: application/json" -d '{"verb": "Identify", "identifier": "test<script>alert(1)</script>"}'
```

Expected response:
```json
{
    "sanitized": {
        "verb": "Identify",
        "identifier": "test&lt;script&gt;alert(1)&lt;/script&gt;"
    }
}
```

---

## Customization

### Payloads Directory
By default, the sanitizer looks for payload files in a directory named `payloads`. You can specify a custom directory by setting the `PAYLOADS_DIR` environment variable.

---

