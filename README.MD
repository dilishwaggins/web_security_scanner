# Web Security Scanner

## Overview
The Web Security Scanner is a lightweight tool designed to help identify security issues in web applications. It includes modules for scanning open ports, checking HTTP security headers, generating firewall rules, and calculating file hashes for integrity verification.

## Features
- **Web App Scanner**: Scans open ports and detects running services.
- **Firewall Rule Generator**: Creates basic firewall rules based on open ports.
- **Hash Calculator**: Computes file hashes using multiple algorithms for integrity verification.

## Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/web_security_scanner.git
   cd web_security_scanner
   ```

2. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```

## Usage

Run the main script to access the scanning features:
```sh
python main.py
```

Each module can also be run individually:
- Web App Scanner:
  ```sh
  python modules/web_app_scanner.py
  ```
- Firewall Rule Generator:
  ```sh
  python modules/firewall_rule_generator.py
  ```
- Hash Calculator:
  ```sh
  python modules/hash_calculator.py
  ```

## Requirements
- Python 3.x
- Required libraries (listed in `requirements.txt`)

## Disclaimer
This tool is for educational and security research purposes only. Do not use it on systems you do not own or have permission to test.

---

