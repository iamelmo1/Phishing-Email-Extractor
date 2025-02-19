import re
import requests
import json
import email
from bs4 import BeautifulSoup
from email import policy
from email.parser import BytesParser
import base64
import codecs
from urllib.parse import urlparse
import socket
import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext


# Function to extract email body
def extract_email_body(msg):
    """Extracts the email body from a .eml file"""
    body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            if content_type == "text/plain" and "attachment" not in content_disposition:
                body += part.get_payload(decode=True).decode("utf-8", errors="ignore")
            elif content_type == "text/html" and not body:  # Prefer text over HTML
                body += part.get_payload(decode=True).decode("utf-8", errors="ignore")
    else:
        body = msg.get_payload(decode=True).decode("utf-8", errors="ignore")

    return body


# Function to extract domains from URLs
def extract_domains_from_urls(urls):
    """Extracts domains from URLs"""
    domains = set()
    for url in urls:
        parsed_url = urlparse(url)
        domains.add(parsed_url.netloc)  # Extract domain name
    return list(domains)


# Function to extract IP addresses
def extract_ip_addresses(email_body, domains):
    """Extracts raw IPs from email body and resolves domain IPs"""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'  # IPv4 pattern
    ip_addresses = set(re.findall(ip_pattern, email_body))  # Extract raw IPs

    # Resolve IP addresses for extracted domains
    for domain in domains:
        try:
            resolved_ip = socket.gethostbyname(domain)  # Get IP from domain
            ip_addresses.add(resolved_ip)
        except socket.gaierror:
            pass  # Ignore domains that cannot be resolved

    return list(ip_addresses)


# Function to decode Unicode
def decode_unicode(text):
    try:
        return codecs.decode(text, 'unicode_escape')
    except Exception:
        return text  # Return as-is if decoding fails


# API Keys (replace with your own API keys)
VIRUSTOTAL_API_KEY = "insert key here"
ABUSEIPDB_API_KEY = "insert key here"


# Function to extract URLs using BeautifulSoup
def extract_urls(email_body):
    """Extracts URLs from email body"""
    soup = BeautifulSoup(email_body, "html.parser")
    links = [a['href'] for a in soup.find_all('a', href=True)]

    # Fallback: Extract URLs using regex if none found
    if not links:
        regex = r"https?://[^\s]+"
        links = re.findall(regex, email_body)

    return links


# Function to check URLs with VirusTotal
def check_url_virustotal(url):
    """Checks URL against VirusTotal"""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        return response.json()

    # If URL not found, submit for scanning
    scan_url = "https://www.virustotal.com/api/v3/urls"
    data = {"url": url}
    scan_response = requests.post(scan_url, headers=headers, data=data)

    return scan_response.json() if scan_response.status_code == 200 else None


# Function to check IPs with AbuseIPDB
def check_ip_abuse(ip):
    """Checks IP against AbuseIPDB"""
    headers = {"key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip}
    response = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
    return response.json() if response.status_code == 200 else None


# Function to analyze an email
def analyze_email(file_path):
    """Analyzes the selected .eml file for phishing indicators"""
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    email_from = msg.get("From")
    email_subject = decode_unicode(msg.get("Subject", ""))
    email_body = extract_email_body(msg)

    urls = extract_urls(email_body)
    domains = extract_domains_from_urls(urls)
    ip_addresses = extract_ip_addresses(email_body, domains)

    # Analyze domains & IPs
    domain_results = {domain: check_url_virustotal(domain) for domain in domains}
    ip_results = {ip: check_ip_abuse(ip) for ip in ip_addresses}

    return {
        "From": email_from,
        "Subject": email_subject,
        "URLs": urls,
        "Domains": domains,
        "IP Addresses": ip_addresses,
        "Domain Analysis": domain_results,
        "IP Analysis": ip_results
    }


### **🔹 GUI Implementation using Tkinter** ###
def select_file():
    """Opens a file dialog to select an .eml file"""
    file_path = filedialog.askopenfilename(filetypes=[("Email Files", "*.eml")])
    if file_path:
        entry_file_path.delete(0, tk.END)
        entry_file_path.insert(0, file_path)


def run_analysis():
    """Runs the phishing analysis and displays the results in the GUI"""
    file_path = entry_file_path.get()
    if not file_path:
        messagebox.showerror("Error", "Please select an .eml file!")
        return

    try:
        report = analyze_email(file_path)
        save_json(report)

        text_output.delete(1.0, tk.END)
        text_output.insert(tk.END, json.dumps(report, indent=4, ensure_ascii=False))
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")


def save_json(report):
    """Saves the phishing analysis report as a JSON file on the desktop"""
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    json_file_path = os.path.join(desktop_path, "phishing_report.json")

    with open(json_file_path, "w", encoding="utf-8") as json_file:
        json.dump(report, json_file, indent=4, ensure_ascii=False)

    messagebox.showinfo("Success", f"Report saved to: {json_file_path}")


# Create the GUI Window
root = tk.Tk()
root.title("Phishing Email Analyzer")
root.geometry("700x500")

# File Selection Section
frame_top = tk.Frame(root)
frame_top.pack(pady=10)

tk.Label(frame_top, text="Select Email (.eml) File:").pack(side=tk.LEFT, padx=5)
entry_file_path = tk.Entry(frame_top, width=50)
entry_file_path.pack(side=tk.LEFT, padx=5)
tk.Button(frame_top, text="Browse", command=select_file).pack(side=tk.LEFT)

# Run Analysis Button
tk.Button(root, text="Run Analysis", command=run_analysis, font=("Arial", 12), bg="green", fg="white").pack(pady=10)

# Output Display Box
text_output = scrolledtext.ScrolledText(root, width=85, height=20, wrap=tk.WORD)
text_output.pack(padx=10, pady=10)

# Run the GUI
root.mainloop()
