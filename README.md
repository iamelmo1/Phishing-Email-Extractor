# Phishing Email Extractor

## About  
Phishing Email Extractor is a Python GUI tool designed to analyze phishing emails. It extracts URLs, domains, and IP addresses from `.eml` files and checks them against VirusTotal and AbuseIPDB to identify potential threats.

## Screenshot

![Screenshot 2025-02-18 180757](https://github.com/user-attachments/assets/5b490887-9c16-474c-af92-a669f1ac3909)


## Features  
- Load and analyze `.eml` files  
- Extract URLs, domains, and IP addresses  
- Check extracted domains and IPs against VirusTotal and AbuseIPDB  
- Save phishing analysis reports as JSON  
- Simple user-friendly GUI using Tkinter  


## Installation  

### Prerequisites  
- Python 3.x installed  
- Required dependencies:  
  ```bash
  pip install requests beautifulsoup4

Run the script:

Bash
python pythonscript.py

Select an .eml file for analysis.
View extracted URLs, domains, and IPs in the output.
The analysis report is saved as a JSON file on the desktop.

API Keys Setup

This tool requires API keys for VirusTotal and AbuseIPDB. Obtain them from the following:

    VirusTotal API
    AbuseIPDB API

Update the script with your API keys:

VIRUSTOTAL_API_KEY = "your-key-here"
ABUSEIPDB_API_KEY = "your-key-here"

Example Output

{
    "From": "phishing@example.com",
    "Subject": "Urgent: Reset Your Password!",
    "URLs": ["http://fakebank.com/login"],
    "Domains": ["fakebank.com"],
    "IP Addresses": ["192.168.1.5"],
    "Domain Analysis": {...},
    "IP Analysis": {...}
}

License

This project is licensed under the MIT License.

This README provides clear installation instructions, usage details, and API setup steps. Let me know if you need modifications.

