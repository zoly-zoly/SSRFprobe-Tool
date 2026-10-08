<div align="center">

# 🎯 SSRFProbe
**High-Performance, Asynchronous SSRF Fuzzer & Filter Bypass Suite**

[![Python Version](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Docker](https://img.shields.io/badge/Docker-Supported-2496ED?style=flat&logo=docker&logoColor=white)]()

*Engineered for security researchers and authorized penetration testers to uncover Server-Side Request Forgery vulnerabilities and header misconfigurations at scale.*

[Features](#-key-features) • [Project Structure](#-project-structure--file-breakdown) • [Installation](#-step-by-step-installation) • [Usage](#-usage-guide) • [Options](#-option-reference) • [Docker](#-docker-support)

</div>

---

## ⚡ Key Features

- **Asynchronous Execution:** Fully non-blocking engine leveraging Python `asyncio` and `httpx` connection pooling for blazing-fast, high-throughput scans.
- **Smart Parameter Fuzzing:** Parses URL query parameters and dynamically injects payloads into suspicious fields (`url`, `dest`, `redirect`, `path`, etc.).
- **Header Injection Pipeline:** Evaluates internal reverse-proxy and origin-tracking headers (`X-Forwarded-For`, `X-Real-IP`, `Referer`, and more).
- **Automated Filter Bypasses:** Includes hexadecimal, octal, decimal (dword), IPv6, and DNS wildcard transformations (e.g., `nip.io`).
- **Cloud Metadata Detection:** Pre-configured probes for AWS, Google Cloud, Azure, DigitalOcean, and Alibaba Cloud internal metadata endpoints.
- **Out-of-Band (OOB) Testing:** Supports custom collaborator domains (Interactsh, Webhooks) for blind SSRF verification.

---

## 📂 Project Structure & File Breakdown

To understand how the project is organized and what each file is responsible for, review the layout below:

```text
ssrfprobe/
├── ssrfprobe/
│   ├── __init__.py      # Initializes the package, exposes version and author metadata.
│   ├── cli.py           # Command-Line Interface (CLI) built with Typer & Rich for formatted terminal output.
│   ├── scanner.py       # Core asynchronous scanning engine, HTTP client management, and heuristic checks.
│   └── payloads.py      # Generates bypass vectors, cloud metadata targets, and suspicious parameter lists.
├── tests/
│   └── test_scanner.py  # Unit tests using pytest to verify payload generation and parameter injection.
├── Dockerfile           # Container configuration file for running the tool inside isolated Docker environments.
├── pyproject.toml       # Modern Python packaging specification and project metadata.
├── requirements.txt     # List of external Python package dependencies.
├── SECURITY.md          # Security policy and responsible disclosure guidelines.
└── README.md            # Comprehensive project documentation and user guide (You are here).
```

---

## 📦 Step-by-Step Installation

Follow these instructions right after cloning the repository to get the tool running on your system. 

### Step 1: Clone the Repository
Open your terminal, clone the project from GitHub, and navigate into the directory:
```bash
git clone https://github.com/yourusername/ssrfprobe.git
cd ssrfprobe
```

### Step 2: Create a Virtual Environment
Isolate your Python environment to avoid dependency conflicts with your OS:
```bash
python -m venv venv
```

### Step 3: Activate the Virtual Environment
- **On Linux / macOS:**
  ```bash
  source venv/bin/activate
  ```
- **On Windows (Command Prompt / PowerShell):**
  ```cmd
  venv\Scripts\activate
  ```

### Step 4: Install the Package
Install the package in editable mode along with all necessary requirements:
```bash
pip install -e .
```

---

## 🚀 Usage Guide

Once installed, the `ssrfprobe` command becomes globally accessible in your terminal. Here is how to use it for various testing scenarios:

### 1. Basic Single Target Scan
To probe a single target URL and check for default parameter or header vulnerabilities:
```bash
ssrfprobe --url "https://target.com/fetch?img=profile.jpg"
```

### 2. Blind SSRF Testing with Out-of-Band (OOB)
If you want to test for blind vulnerabilities where responses are not directly reflected, supply your collaborator server domain (like interact.sh or Burp Collaborator):
```bash
ssrfprobe --url "https://target.com/api/proxy" --collab "xyz.oastify.com"
```

### 3. Bulk Scanning from a File & Exporting Results
To scan multiple URLs listed in a text file (`targets.txt`), adjust concurrency for speed, set a timeout, and save results to a JSON file:
```bash
ssrfprobe --file targets.txt --concurrency 25 --timeout 6.0 --output results.json
```

---

## ⚙️ Option Reference

Below is the complete reference table for all available command-line switches and flags:

| Option / Flag | Shorthand | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--url` | `-u` | `TEXT` | `None` | Specifies a single target URL to probe. |
| `--file` | `-f` | `PATH` | `None` | Path to a text file containing a list of target URLs (one per line). |
| `--concurrency` | `-c` | `INTEGER` | `15` | Sets the maximum number of concurrent asynchronous workers. |
| `--timeout` | `-t` | `FLOAT` | `7.0` | Sets the HTTP request timeout limit in seconds. |
| `--collab` | *None* | `TEXT` | `""` | Out-of-band collaborator domain for tracking blind SSRF requests. |
| `--output` | `-o` | `PATH` | `None` | Path to export successful scan findings into a structured JSON file. |

---

## 🐳 Docker Support

If you prefer not to configure a local Python environment, you can run SSRFProbe securely inside a Docker container. 

### Step 1: Build the Docker Image
Make sure you are in the root directory containing the `Dockerfile`, then build the image:
```bash
docker build -t ssrfprobe .
```

### Step 2: Run Scans via Docker
Execute the tool directly inside the container by passing the arguments:
```bash
docker run --rm -it ssrfprobe --url "https://example.com/api?path=home"
```

**Using Local Files with Docker:**
If you need to read a local target list file (e.g., `targets.txt`) and save output reports back to your host machine, mount your current working directory using `-v`:
```bash
docker run --rm -it -v $(pwd):/app ssrfprobe --file targets.txt --output results.json
```

---

## 🛡️ Responsible Disclosure & Ethics

> **Disclaimer:** This tool is designed strictly for authorized security assessments, academic research, and bug bounty programs within explicit scope. Never run this tool against any system without prior written permission from the owner. The author assumes no liability for misuse.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
