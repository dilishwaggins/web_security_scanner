import nmap
import requests
import json
from bs4 import BeautifulSoup

def scan_ports(target):
    """ Scans open ports and services using Nmap. """
    print("\n[+] Starting Nmap Scan...")
    scanner = nmap.PortScanner()

    try:
        scanner.scan(target, arguments='-sV')
    except Exception as e:
        return {"error": f"Nmap scan failed: {e}"}

    open_ports = []
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                service = scanner[host][proto][port]
                open_ports.append({
                    'port': port,
                    'state': service['state'],
                    'name': service['name'],
                    'product': service.get('product', 'unknown'),
                    'version': service.get('version', 'unknown')
                })

    return open_ports

def check_headers(url):
    """ Checks security headers for a given URL. """
    print("\n[+] Checking HTTP Security Headers...")
    headers_to_check = [
        'Content-Security-Policy',
        'X-Frame-Options',
        'Strict-Transport-Security',
        'X-Content-Type-Options',
        'Referrer-Policy'
    ]
    findings = {}

    try:
        response = requests.get(url, timeout=5)
        for header in headers_to_check:
            findings[header] = response.headers.get(header, 'MISSING')
    except requests.exceptions.RequestException as e:
        return {"error": f"HTTP request failed: {e}"}

    return findings

def save_results(results, filename="scan_results.json"):
    """ Saves the scan results to a JSON file. """
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)
    print(f"\n[+] Results saved to {filename}")

def run():
    target = input("Enter target IP or domain: ").strip()

    # Port Scan
    ports = scan_ports(target)
    print("\n[+] Open Ports:")
    if "error" in ports:
        print(ports["error"])
    else:
        for p in ports:
            print(f" - {p['port']}/tcp | {p['state']} | {p['name']} | {p['product']} {p['version']}")

    # Header Scan (Try HTTPS first, fallback to HTTP)
    for protocol in ["https", "http"]:
        url = f"{protocol}://{target}"
        headers = check_headers(url)
        if "error" not in headers:
            print(f"\n[+] HTTP Security Headers ({protocol.upper()}):")
            for header, value in headers.items():
                print(f" - {header}: {value}")

            print("\n[!] Recommendations:")
            for header, value in headers.items():
                if value == 'MISSING':
                    print(f"   - Consider setting {header} for better security.")
            break
        else:
            print(headers["error"])

    # Save results
    results = {"target": target, "ports": ports, "headers": headers}
    save_results(results)

if __name__ == "__main__":
    run()
