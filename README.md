# SSL Authority Checker

## Summary

The **SSL Authority Checker** is a DevSecOps VM Python automation tool that reads a list of hosts from a CSV file, retrieves their SSL certificate information (trusted authority and serial numbers), and verifies if the certificates are issued by the trusted certificate authorities listed for the organization. It logs the results, saves the certificate serial numbers to a JSON file, and can send email notifications if any hosts use untrusted certificate authorities.

---

## Features

- Reads hosts from a CSV file.
- Retrieves SSL certificate chains for each host.
- Extracts certificate chain length, issuer, and serial numbers.
- Checks if the issuer matches a list of trusted authorities.
- Logs the output to a timestamped .log file (same dir).
- Saves serial numbers and issuer info to extracted_serials.json.
- Sends email alerts for untrusted certificate authorities (SMTP and app password config required).
- .env file for secure credential usage.

---

## Prerequisites

- Python 3.7 or higher
- Required Python packages:
  - `pyOpenSSL`
  - `python-dotenv`
  
You can install dependencies via pip:
`pip install pyOpenSSL python-dotenv`


## Host File
Create your hosts.csv file one per line, i.e
www.google.com
www.test.com
www.example.com

## ENV File
Your env file should contain SMTP credentials for email notification pager usage, this is using the 
'app password' feature to enable email sending and receiving through my script.


```
EMAIL_ENABLED=True
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password_here
EMAIL_FROM=your_email@gmail.com
EMAIL_TO=recipient_email@example.com
```

## Usage
The usage is simple if you have a venv and the pre-reqs installed, simply run:
- python SSL_Authority_Checker.py

hosts.csv includes an edge case of badssl.com which does not have a trusted authority within the allow list, see email_alert.png for the alert POC.

## Logging
Logs are created from the script processes and results and are stored in SSL_result_YYYYMMDD_HHMMSS.log
which are timestamped.

## Credit
Cameron Noakes
This script is provided as-is, without warranty. Use it responsibly and at your own risk. Not liable for any actions taken.
