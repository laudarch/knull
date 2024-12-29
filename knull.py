#!/usr/bin/env python3
#
# coded by laudarch
#

import subprocess
import json
import requests
from concurrent.futures import ThreadPoolExecutor
import argparse
import os

# Configuration
RATE = 10000  # Packets per second for Masscan
OUTPUT_FILE = "masscan_output.json"
HTTP_RESULTS = "http_results.txt"
HTTPS_RESULTS = "https_results.txt"
THREADS = 100  # Concurrent threads for fetching pages

# Step 1: Run Masscan on a CIDR Range
def run_masscan(ip_range):
    print(f"[+] Scanning {ip_range} with Masscan...")
    output_file = f"masscan_{ip_range.replace('/', '_')}.json"
    command = [
        "masscan",
        ip_range,
        "--ports", "80,443",
        "--rate", str(RATE),
        "-oJ", output_file
    ]
    subprocess.run(command, check=True)
    print(f"[+] Scan complete. Results saved to {output_file}")
    return output_file

# Step 2: Parse Masscan Results
def parse_masscan_results(output_file):
    print(f"[+] Parsing results from {output_file}...")
    with open(output_file, "r") as f:
        results = json.load(f)
    services = []
    for entry in results:
        ip = entry["ip"]
        for port in entry["ports"]:
            services.append((ip, port["port"]))
    print(f"[+] Found {len(services)} services in {output_file}.")
    return services

# Step 3: Fetch Webpage Content
#def fetch_webpage(ip, port):
#    protocol = "https" if port == 443 else "http"
#    url = f"{protocol}://{ip}:{port}"
#    try:
#        response = requests.get(url, verify=False, timeout=5)
#        print(f"[+] Successfully fetched {url}")
#        return ip, port, response.text[:500]  # Limit content preview to 500 chars
#    except requests.RequestException as e:
#        print(f"[-] Failed to fetch {url}: {e}")
#        return ip, port, "ERROR"
def fetch_webpage(ip, port):
    protocol = "https" if port == 443 else "http"
    url = f"{protocol}://{ip}:{port}"

    try:
        # Parse and sanitize the URL
        parsed = urlparse(url)
        sanitized_hostname = parsed.hostname.lstrip(".") if parsed.hostname else None
        if not sanitized_hostname:
            print(f"[-] Invalid URL: {url}")
            return ip, port, "INVALID_URL"
        
        # Rebuild the sanitized URL
        sanitized_url = urlunparse(parsed._replace(netloc=f"{sanitized_hostname}:{port}"))
        
        # Make the request
        response = requests.get(sanitized_url, verify=False, timeout=5)
        print(f"[+] Successfully fetched {sanitized_url}")
        return ip, port, response.text[:500]  # Limit content preview to 500 chars
    except requests.RequestException as e:
        print(f"[-] Failed to fetch {url}: {e}")
        return ip, port, "ERROR"

# Step 4: Save Results
def save_results(results):
    with open(HTTP_RESULTS, "a") as http_file, open(HTTPS_RESULTS, "a") as https_file:
        for ip, port, content in results:
            if port == 80:
                http_file.write(f"{ip}:{port}\nContent: {content}\n\n")
            elif port == 443:
                https_file.write(f"{ip}:{port}\nContent: {content}\n\n")
    print(f"[+] Results saved to {HTTP_RESULTS} and {HTTPS_RESULTS}")

# Step 5: Main Workflow
def main():
    parser = argparse.ArgumentParser(description="Masscan HTTP/HTTPS Scanner with Page Content Retrieval")
    parser.add_argument("cidr_file", help="File containing CIDR ranges (one per line)")
    args = parser.parse_args()
    
    cidr_file = args.cidr_file
    
    if not os.path.isfile(cidr_file):
        print(f"[-] Error: File '{cidr_file}' not found.")
        exit(1)
    
    with open(cidr_file, "r") as f:
        cidr_ranges = [line.strip() for line in f if line.strip()]
    
    if not cidr_ranges:
        print("[-] Error: No CIDR ranges found in the file.")
        exit(1)
    
    for cidr in cidr_ranges:
        masscan_output = run_masscan(cidr)
        services = parse_masscan_results(masscan_output)
        
        results = []
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            future_to_service = {executor.submit(fetch_webpage, ip, port): (ip, port) for ip, port in services}
            for future in future_to_service:
                result = future.result()
                results.append(result)
        
        save_results(results)
        print(f"[+] Completed processing for {cidr}\n")

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()

