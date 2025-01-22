# OAI-PMH Fuzzer and Sanitizer

The **OAI-PMH Fuzzer** and **Sanitizer** are tools designed to test OAI-PMH endpoints and validate input against attacks such as DTD injections and other malicious inputs. These tools provide an integrated approach to testing and securing OAI-PMH implementations.

## Features

### OAI-PMH Fuzzer
1. **Fuzz Testing**
   - Generates random and malicious input, including:
     - Poorly formatted parameters
     - Invalid dates
     - XXE and DTD attacks
   - Tests multiple OAI-PMH requests, such as `Identify`, `ListRecords`, and `GetRecord`.

2. **Logging**
   - **HTTP Status Codes**: Logs response status codes, response times, and HTTP versions to a separate log file.
   - **Server Information**: Logs headers and server responses for later analysis.

3. **Result Analysis**
   - Summarizes status codes and response times.
   - Identifies trends in server responses.

### OAI-PMH Sanitizer
1. **Sanitization**
   - Filters input parameters to block malicious input, such as DTD and SYSTEM calls.
   - Replaces suspicious input with `[BLOCKED]`.

2. **Proxy Functionality**
   - Receives requests, sanitizes parameters, and forwards them to the configured OAI-PMH endpoint.

3. **Logging**
   - Records blocked requests, including the type of attack, for security analysis.

4. **Server Implementation**
   - Runs a local HTTP server (`http://localhost:8081`) to process sanitized requests.

---

## Configuration and Requirements

### Requirements
- **Python 3.8+**
- Required Python packages:
  - `httpx`
  - `requests`

### Payloads
- **Payloads Directory**: Place test payloads in the `payloads` directory or use the existing payloads and `.dtd` file examples. You can host these files locally. Each payload is used to generate requests. Both text-based and special character payloads are supported.

---

## Usage

### 1. Using the Fuzzer Independently
The Fuzzer can be used independently without the Sanitizer. This allows you to directly test an OAI-PMH endpoint for vulnerabilities and how it handles malicious input. The log files provide insights into the handling of requests.

Start the Fuzzer with:

```bash
python3 fuzzer.py
```

The Fuzzer generates requests, logs responses, and analyzes results.

### 2. Using the Fuzzer with the Sanitizer

If you want to filter and secure input before it is sent to an OAI-PMH endpoint, use the Sanitizer as a proxy. This setup is intended as a starting point to protect the OAI-PMH endpoint and/or gain insight into how the endpoint handles malicious input. The log files provide detailed information on request handling.

1.  Start the Sanitizer server:

    ```bash
    python3 sanitizer.py
    ```
The server runs on http://localhost:8081.

2.  Configure the Fuzzer to send requests to the Sanitizer server and then start the Fuzzer:

    ```bash
    python3 fuzzer.py
    ```

### 3. Analyzing Results

Check the following log files:
- **`oai_pmh_fuzzer.log`**: Detailed log of fuzzing activities.
- **`oai_pmh_status_codes.log`**: Summary of HTTP status codes and response times.
- **`oai_pmh_server_info.log`**: Details of server headers and responses.
- **`oai_sanitizer.log`**: Blocked requests and sanitization results.

## Contact

For questions or feedback, please contact [Rody Jordens](mailto:rodyjordens@pm.me).