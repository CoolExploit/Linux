# Everything is still underdeveloped😭😭
import os
import time
import requests
import socket
from urllib.parse import urlparse
import json
import re
import subprocess
import shodan
import mechanize

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')
# Menu Ofc
def print_menu():
    clear_screen()
    print(f"""
  ____  ____   ___  
 |  _ \/ ___| / _ \ 
 | |_) \___ \| | | |
 |  __/ ___) | |_| |
 |_|   |____/ \__\_|

Welcome to PSQ - Python Security Query Tool

Please choose an option:
1. Scan for API Vulnerabilities
2. Scan for Web Application Vulnerabilities
3. Perform Network Reconnaissance
4. Check for Open Ports
5. Check for Security Headers
6. Check SSL/TLS Configuration
7. Reverse Engineer Web Application
8. Find API Keys using Shodan
9. Backup and Restore Data
10. Exit
""")
# Functions/Logic 
def scan_api_vulnerabilities():
    url = input("Enter the API URL to scan: ")
    print(f"Scanning {url} for vulnerabilities...")
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print("API is reachable.")

            if 'application/json' not in response.headers.get('Content-Type', ''):
                print("Warning: API response is not in JSON format.")
            if 'Authorization' not in response.headers:
                print("Warning: No Authorization header found. This may indicate a lack of security.")

            api_key = find_api_key(response.headers, response.text)
            if api_key:
                print(f"Warning: API key found in response: {api_key}")

            cors_vulnerability = check_cors_vulnerability(url)
            if cors_vulnerability:
                print(f"Warning: CORS vulnerability found: {cors_vulnerability}")

            rate_limiting_vulnerability = check_rate_limiting_vulnerability(url)
            if rate_limiting_vulnerability:
                print(f"Warning: Rate limiting vulnerability found: {rate_limiting_vulnerability}")
        else:
            print(f"API returned status code: {response.status_code}")
    except Exception as e:
        print(f"Error accessing API: {e}")
    time.sleep(2)

def scan_web_application_vulnerabilities():
    url = input("Enter the web application URL to scan: ")
    print(f"Scanning {url} for vulnerabilities...")
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print("Web application is reachable.")

            if "X-Frame-Options" not in response.headers:
                print("Warning: X-Frame-Options header not found. This may indicate a lack of security.")
            if "X-Content-Type-Options" not in response.headers:
                print("Warning: X-Content-Type-Options header not found. This may indicate a lack of security.")

            cors_vulnerability = check_cors_vulnerability(url)
            if cors_vulnerability:
                print(f"Warning: CORS vulnerability found: {cors_vulnerability}")


            rate_limiting_vulnerability = check_rate_limiting_vulnerability(url)
            if rate_limiting_vulnerability:
                print(f"Warning: Rate limiting vulnerability found: {rate_limiting_vulnerability}")

            api_key = find_api_key(response.headers, response.text)
            if api_key:
                print(f"Warning: API key found in response: {api_key}")

            browser = mechanize.Browser()
            browser.open(url)
            form = browser.get_form()
            if form:
                print("Performing reverse engineering using Mechanize...")


                with open("response.html", "w") as f:
                    f.write(response.read())
                print("Response saved to response.html")
            else:
                print("No form found on the web page.")
        else:
            print(f"Web application returned status code: {response.status_code}")
    except Exception as e:
        print(f"Error accessing web application: {e}")
    time.sleep(2)

def find_api_key(headers, body):
    api_key = None
    for header, value in headers.items():
        if "api-key" in header.lower() or "authorization" in header.lower():
            api_key = value
            break
    if not api_key:
        try:
            json_body = json.loads(body)
            for key, value in json_body.items():
                if "api-key" in key.lower() or "authorization" in key.lower():
                    api_key = value
                    break
        except json.JSONDecodeError:
            pass
    if not api_key:
        api_key_regex = r"[a-zA-Z0-9_\-]+=[a-zA-Z0-9_\-]+"
        regex_matches = re.findall(api_key_regex, body)
        if regex_matches:
            api_key = regex_matches[0]
    return api_key

def check_cors_vulnerability(url):
    try:
        response = requests.options(url, headers={"Origin": "http://example.com"})
        if response.headers.get("Access-Control-Allow-Origin") == "*":
            return "CORS vulnerability found: Access-Control-Allow-Origin header set to *"
    except Exception as e:
        print(f"Error checking CORS vulnerability: {e}")
    return None

def check_rate_limiting_vulnerability(url):
    try:
        for i in range(10):
            response = requests.get(url)
            if response.status_code != 200:
                return f"Rate limiting vulnerability found: {response.status_code} status code returned after {i} requests"
    except Exception as e:
        print(f"Error checking rate limiting vulnerability: {e}")
    return None

def reverse_engineer_web_application():
    url = input("Enter the web application URL to reverse engineer: ")
    print(f"Reverse engineering {url}...")

    browser = mechanize.Browser()
    browser.open(url)
    form = browser.get_form()
    if form:
        print("Performing reverse engineering using Mechanize...")

        response = browser.submit(form)

        with open("response.html", "w") as f:
            f.write(response.read())
        print("Response saved to response.html")
    else:
        print("No form found on the web page.")

def find_api_keys_using_shodan(api_key):
    api_key = api_key.strip()
    shodan.api.key = api_key
    results = shodan.host.search()
    found_api_keys = []
    for result in results:
        if api_key in result.data.get("api_key", ""):
            found_api_keys.append(result.ip_str)
    return found_api_keys

def backup_data(filename):

    pass

def restore_data(filename):
  
    pass

def main():
    while True:
        print_menu()
        choice = input("Enter your choice: ")
        if choice == "1":
            scan_api_vulnerabilities()
        elif choice == "2":
            scan_web_application_vulnerabilities()
        elif choice == "3":

            pass
        elif choice == "4":

            pass
        elif choice == "5":

            pass
        elif choice == "6":

            pass
        elif choice == "7":
            reverse_engineer_web_application()
        elif choice == "8":
            api_key = input("Enter the API key to search for: ")
            found_api_keys = find_api_keys_using_shodan(api_key)
            if found_api_keys:
                print(f"API key found on the following hosts: {', '.join(found_api_keys)}")
            else:
                print("API key not found.")
        elif choice == "9":
            backup_filename = input("Enter the filename to backup: ")
            backup_data(backup_filename)
        elif choice == "10":
            restore_filename = input("Enter the filename to restore from: ")
            restore_data(restore_filename)
        else:
            print("Invalid choice. Please try again.")
        print("Do you want to:")
        print("1. Use PSQ again")
        print("2. Exit")
        choice = input("Enter your choice: ")
        if choice == "2":
            break
        elif choice != "1":
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
