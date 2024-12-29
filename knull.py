#!/usr/bin/env python3
#
# coded by laudarch
#

import os
import sys
import json
import signal
import argparse
import requests
import threading
import subprocess

from requests.adapters import HTTPAdapter
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urlunparse
from urllib3.poolmanager import PoolManager
from urllib3.util.ssl_ import create_urllib3_context
from urllib3.exceptions import LocationParseError

# Configuration
RATE = 10000  # Packets per second for Masscan
THREADS = 100 # Concurrent threads for fetching pages

IPS_FILE = "ips.txt"
OUTPUT_FILE = "masscan_output.json"
SESSION_FILE = "scanner_session.json"
HTTP_RESULTS_FILE = "http_results.txt"
HTTPS_RESULTS_FILE = "https_results.txt"

MASSCAN_FOLDER = "masscan/"
RESULTS_FOLDER = "results/"
MAIN_SESSION_FOLDER = "sessions/"

# Custom SSL adapter
class SSLAdapter(HTTPAdapter):
    def __init__(self, **kwargs):
        self.ssl_context = create_urllib3_context()
        # Configure SSL context to accept any hostname for SNI
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = False
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self.ssl_context
        return super().init_poolmanager(*args, **kwargs)

# Load session state
def load_session():
    sessionfile = os.path.join(sessionfolder, SESSION_FILE)
    if os.path.isfile(sessionfile):
        with open(sessionfile, "r") as f:
            return json.load(f)
    return {"completed": [], "in_progress": []}

# Save session state
def save_session(state):
    sessionfile = os.path.join(sessionfolder, SESSION_FILE)
    with open(sessionfile, "w") as f:
        json.dump(state, f, indent=4)
    print(f"[+] Session saved to {sessionfile}")

# Signal handler for graceful termination
def signal_handler(sig, frame):
    print("\n[!] Interruption detected. Saving session...")
    save_session(state)
    sys.exit(0)

# Run Masscan on a CIDR Range
def run_masscan(ip_range):
    print(f"[+] Scanning {ip_range} with Masscan...")
    output_file = f"masscan_{ip_range.replace('/', '_')}.json"
    output_file = os.path.join(sessionmasscan, output_file)
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

# Parse Masscan Results
def parse_masscan_results(output_file):
    print(f"[+] Parsing results from {output_file}...")
    if os.path.getsize(output_file) == 0:
        print(f"[-] Error: The file {output_file} is empty.")
        return []

    try:
        with open(output_file, "r") as f:
            results = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[-] Error: Failed to parse JSON from {output_file}. {e}")
        return []

    services = []
    for entry in results:
        ip = entry.get("ip")
        for port in entry.get("ports", []):
            services.append((ip, port["port"]))
    print(f"[+] Found {len(services)} services in {output_file}.")
    return services

# Fetch Webpage Content
def fetch_webpage(ip, port):
    protocol = "https" if port == 443 else "http"
    url = f"{protocol}://{ip}:{port}"

    try:
        # header spoofing
        headers = {"Host": ip}
        
        # Handle HTTPS with custom SSL adapter
        if protocol == "https":
            session = requests.Session()
            session.mount("https://", SSLAdapter())
            response = session.get(url, headers=headers, verify=False, timeout=5)
        else:
            response = requests.get(url,  headers=headers, verify=False, timeout=5)
        
        print(f"[+] Successfully fetched {url}")
        return ip, port, response.text 
    except requests.RequestException as e:
        print(f"[-] Failed to fetch {url}: {e}")
        return ip, port, "ERROR"
    except LocationParseError as e: 
        print(f"URL: {url}\n An error occurred while parsing the location: {e}\nStatus: Error")
        return ip, port, "ERROR"

# Save Results
def save_results(results):
    http_filename = os.path.join(sessionresults, HTTP_RESULTS_FILE)
    https_filename = os.path.join(sessionresults, HTTPS_RESULTS_FILE)
    ips_filename = os.path.join(sessionfolder, IPS_FILE)
    with open(http_filename, "a") as http_file, open(https_filename, "a") as https_file, open(ips_filename, "a") as ips_file:
        for ip, port, content in results:
            if port == 80:
                ips_file.write(f"http://{ip}:{port}\n")
                http_file.write(f"http://{ip}:{port}\nContent: {content}\n\n")
            elif port == 443:
                ips_file.write(f"https://{ip}:{port}\n")
                https_file.write(f"https://{ip}:{port}\nContent: {content}\n\n")
    print(f"[+] Results saved to {http_filename} and {https_filename}")

# Main Workflow with Multithreading
def main():
    global state
    global sessionfolder
    global sessionmasscan
    global sessionresults

    parser = argparse.ArgumentParser(description="Masscan HTTP/HTTPS Scanner with Page Content Retrieval and Resumption")
    parser.add_argument("cidr_file", help="File containing CIDR ranges (one per line)")
    parser.add_argument("session_name", help="Session/Project name")
    args = parser.parse_args()

    cidr_file = args.cidr_file
    session_name = args.session_name

    if not os.path.isfile(cidr_file):
        print(f"[-] Error: File '{cidr_file}' not found.")
        exit(1)
    
    # Create folders
    sessionfolder = os.path.join(MAIN_SESSION_FOLDER, session_name)
    sessionmasscan = os.path.join(sessionfolder, MASSCAN_FOLDER)
    sessionresults = os.path.join(sessionfolder, RESULTS_FOLDER)
    
    os.makedirs(os.path.dirname(MAIN_SESSION_FOLDER), exist_ok=True)
    os.makedirs(os.path.dirname(sessionfolder), exist_ok=True)
    os.makedirs(os.path.dirname(sessionmasscan), exist_ok=True)
    os.makedirs(os.path.dirname(sessionresults), exist_ok=True)
    
    state = load_session()
    
    with open(cidr_file, "r") as f:
        cidr_ranges = [line.strip() for line in f if line.strip()]
    
    # Skip completed CIDR ranges
    remaining_cidrs = [cidr for cidr in cidr_ranges if cidr not in state["completed"]]

    if not remaining_cidrs:
        print("[+] All CIDR ranges already processed.")
        return

    try:
        for cidr in remaining_cidrs:
            print(f"[+] Processing CIDR: {cidr}")
            state["in_progress"].append(cidr)  # Mark as in progress
            save_session(state)
            # Perform scan and process
            masscan_output = run_masscan(cidr)
            services = parse_masscan_results(masscan_output)
            
            results = []
            with ThreadPoolExecutor(max_workers=THREADS) as executor:
                future_to_service = {executor.submit(fetch_webpage, ip, port): (ip, port) for ip, port in services}
                for future in future_to_service:
                    result = future.result()
                    results.append(result)
            
            save_results(results)
            state["completed"].append(cidr)  # Mark as completed
            state["in_progress"].remove(cidr)  # Remove from in-progress
            save_session(state)
            print(f"[+] Completed processing for {cidr}\n")
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C detected. Saving session...")
        save_session(state)
        sys.exit(0)
    except Exception as e:
        print(f"[-] Error occurred: {e}")
        save_session(state)
        raise

# Main
if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    main()
