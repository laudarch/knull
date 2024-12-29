#!/usr/bin/env python3
#
# coded by laudarch
#

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options 
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import os
import time
import argparse
import re
import json
import signal
import sys

SESSION_FILE = "screenshots_session.json"
IPS_FILE = "ips.txt"
MAIN_SESSION_FOLDER = "sessions/"
SCREENSHOTS_FOLDER = "screenshots/"

# Flag to indicate if the program is interrupted
interrupted = False

def sanitize_filename(url):
    # Replace http:// and https:// with scr_
    url = re.sub(r'^https?://', 'scr_', url)
    # Remove :80 and /443
    url = re.sub(r':80', '_http', url)
    url = re.sub(r':443', '_https', url)
    # Replace invalid filename characters with underscores
    return re.sub(r'[\\/*?\"<>|]', '_', url)

def save_session(processed_urls):
    # Save the set of processed URLs to a session file
    with open(sessionfile, "w") as session_file:
        json.dump(list(processed_urls), session_file)

def load_session():
    # Load the set of processed URLs from the session file
    if os.path.exists(sessionfile):
        with open(sessionfile, "r") as session_file:
            return set(json.load(session_file))
    return set()

def take_screenshot(url, filename):
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--ignore-certificate-errors")
    options.add_argument("--start-maximized")

    driver = webdriver.Chrome(options=options)

    try:
        # Navigate to the URL
        driver.get(url)

        # Wait for page to fully load (adjust as needed)
        wait = WebDriverWait(driver, 100)
        wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))

        # Set window size to capture full page screenshot
        total_width = driver.execute_script("return document.body.scrollWidth")
        total_height = driver.execute_script("return document.body.scrollHeight")
        driver.set_window_size(total_width, total_height)

        # Take screenshot of the entire page
        filepath = os.path.join(sessionscreenshot, filename)
        driver.save_screenshot(filepath)
    except Exception as e:
        print(f"Error taking screenshot for {url}: {e}")
    finally:
        # Close the browser
        driver.quit()

def signal_handler(sig, frame):
    global interrupted
    print("\nInterrupt received, saving session and exiting...")
    interrupted = True
    save_session(processed_urls)
    sys.exit(0)

# Main
if __name__ == "__main__":
    global sessionfile
    global session_name
    global sessionfolder
    global sessionscreenshot

    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description="Take screenshots from a list of HTTP/HTTPS URLs")
    parser.add_argument("file" , nargs='?', help="Path to the file containing URLs")
    parser.add_argument("session_name", help="Session/Project name")
    args = parser.parse_args()

    session_name = args.session_name
    sessionfolder = os.path.join(MAIN_SESSION_FOLDER, session_name)
    sessionfile = os.path.join(sessionfolder, SESSION_FILE)
    sessionscreenshot = os.path.join(sessionfolder, SCREENSHOTS_FOLDER)

    ips_file = args.file if args.file else os.path.join(sessionfolder, IPS_FILE)

    # Ensure the folders exist
    os.makedirs(os.path.dirname(MAIN_SESSION_FOLDER), exist_ok=True)
    os.makedirs(os.path.dirname(sessionfolder), exist_ok=True)
    os.makedirs(os.path.dirname(sessionscreenshot), exist_ok=True)

    # Load session
    processed_urls = load_session()

    # Read URLs from file
    with open(ips_file, "r") as file:
        urls = file.readlines()

    for url in urls:
        if interrupted:
            break

        url = url.strip()
        if url and url not in processed_urls:
            # Sanitize the filename based on the URL
            filename = sanitize_filename(url) + ".png"
            filepath = os.path.join(sessionscreenshot, filename)
            print(f"Processing {url} -> {filepath}")
            take_screenshot(url, filename)

            # Update the session
            processed_urls.add(url)
            save_session(processed_urls)

    print("Processing complete.")
