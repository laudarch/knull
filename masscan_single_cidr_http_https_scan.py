#!/usr/bin/env python3
#
# coded by laudarch
#

import subprocess
import json
import requests
from concurrent.futures import ThreadPoolExecutor
import argparse

# Configuration
RATE = 10000  # Packets per second for Masscan
OUTPUT_FILE = "masscan_output.json"
HTTP_RESULTS = "http_results.txt"
HTTPS_RESULTS = "https_results.txt"
THREADS = 100  # Concurrent threads for fetching pages

# Step 1: Run Masscan
def run_masscan(ip_range):
    print("[+] Running Masscan to scan for HTTP and HTTPS services...")
    command = [
        "masscan",
        ip_range,
        "--ports", "80,443",
        "--rate", str(RATE),
        "-oJ", OUTPUT_FILE
    ]
    subprocess.run(command, check=True)
    print(f"[+] Masscan scan complete. Results saved to {OUTPUT_FILE}")

# Step 2: Parse Masscan Results
def parse_masscan_results():
    print("[+] Parsing Masscan results...")
    with open(OUTPUT_FILE, "r") as f:
        results = json.load(f)
    services = []
    for entry in results:
        ip = entry["ip"]
        for port in entry["ports"]:
            services.append((ip, port["port"]))
    print(f"[+] Found {len(services)} services.")
    return services

# Step 3: Fetch Webpage Content
def fetch_webpage(ip, port):
    protocol = "https" if port == 443 else "http"
    url = f"{protocol}://{ip}:{port}"
    try:
        response = requests.get(url, verify=False, timeout=5)
        print(f"[+] Successfully fetched {url}")
        return ip, port, response.text[:500]  # Limit content preview to 500 chars
    except requests.RequestException as e:
        print(f"[-] Failed to fetch {url}: {e}")
        return ip, port, "ERROR"

# Step 4: Save Results
def save_results(results):
    with open(HTTP_RESULTS, "w") as http_file, open(HTTPS_RESULTS, "w") as https_file:
        for ip, port, content in results:
            if port == 80:
                http_file.write(f"{ip}:{port}\nContent: {content}\n\n")
            elif port == 443:
                https_file.write(f"{ip}:{port}\nContent: {content}\n\n")
    print(f"[+] Results saved to {HTTP_RESULTS} and {HTTPS_RESULTS}")

# Step 5: Main Workflow
def main():
    parser = argparse.ArgumentParser(description="Masscan HTTP/HTTPS Scanner with Page Content Retrieval")
    parser.add_argument("ip_range", help="IP range to scan (e.g., 192.168.1.0/24)")
    args = parser.parse_args()
    
    ip_range = args.ip_range
    run_masscan(ip_range)
    services = parse_masscan_results()
    
    results = []
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        future_to_service = {executor.submit(fetch_webpage, ip, port): (ip, port) for ip, port in services}
        for future in future_to_service:
            result = future.result()
            results.append(result)
    
    save_results(results)

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()

