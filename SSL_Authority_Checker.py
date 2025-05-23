import csv
import ssl
import socket
import json
import datetime
import logging
import smtplib
from email.message import EmailMessage
from OpenSSL import crypto
from dotenv import load_dotenv
import os

# Load environment variables from .env
load_dotenv()

EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "False").lower() == "true"
SMTP_SERVER = os.getenv("SMTP_SERVER", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
EMAIL_FROM = os.getenv("EMAIL_FROM", "")
EMAIL_TO = os.getenv("EMAIL_TO", "")

TRUSTED_AUTHORITIES = [
    "Let's Encrypt",
    "DigiCert",
    "WR2",
    "Apple Public",
    "Microsoft Azure",
    "E6",
    "WE1",
    "Thawte TLS RSA CA G1",
    "Sectigo",
    "GlobalSign",
    "GoDaddy",
    "COMODO",
    "Entrust"
]

def read_hosts_from_csv(file_path):
    print("Reading hosts from CSV: " + file_path)
    hosts = []
    try:
        with open(file_path, newline='') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if row:
                    host = row[0].strip()
                    print("Host loaded: " + host)
                    hosts.append(host)
    except Exception as e:
        print("Error reading CSV file: " + str(e))
        logging.error("Error reading CSV file: " + str(e))
    return hosts

def get_certificate_chain(host, port=443):
    print("Connecting to host: " + host)
    try:
        conn = socket.create_connection((host, port), timeout=5)
        context = ssl.create_default_context()
        sock = context.wrap_socket(conn, server_hostname=host)
        der_certs = sock.getpeercert(True)
        pem_cert = ssl.DER_cert_to_PEM_cert(der_certs)
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert)
        certs = [x509]
        print("Retrieved certificate for host: " + host)
        logging.info("Certificate retrieved from host: " + host)
        return certs
    except Exception as e:
        print("Failed to retrieve certificate from " + host + ": " + str(e))
        logging.error("Failed to retrieve certificate from " + host + ": " + str(e))
        return []

def parse_certificate_chain(chain, host):
    if not chain:
        print("No certificate chain to parse for host: " + host)
        return

    try:
        issuing_company = chain[0].get_issuer().CN
        serial_numbers = [cert.get_serial_number() for cert in chain]
        print("Host: " + host)
        print("Issuer: " + issuing_company)
        print("Certificate chain length: " + str(len(chain)))
        print("Serial numbers: " + str(serial_numbers))
        logging.info("Issuer for " + host + ": " + issuing_company)
        logging.info("Serial numbers for " + host + ": " + str(serial_numbers))
        if is_trusted_authority(issuing_company):
            print("Trusted Authority: " + issuing_company)
            logging.info("Trusted Authority: " + issuing_company)
        else:
            print("Untrusted Authority: " + issuing_company)
            logging.warning("Untrusted Authority: " + issuing_company)
        return issuing_company, serial_numbers
    except Exception as e:
        print("Error parsing certificate for " + host + ": " + str(e))
        logging.error("Error parsing certificate for " + host + ": " + str(e))

def is_trusted_authority(issuer_name):
    for trusted in TRUSTED_AUTHORITIES:
        if trusted.lower() in issuer_name.lower():
            return True
    return False

def save_serials(serials, file_path='extracted_serials.json'):
    try:
        with open(file_path, 'w') as f:
            json.dump(serials, f, indent=4)
        print("Saved serial numbers to " + file_path)
        logging.info("Serial numbers saved to " + file_path)
    except Exception as e:
        print("Failed to save serials: " + str(e))
        logging.error("Failed to save serials: " + str(e))

def send_email_notification(untrusted_hosts):
    if not EMAIL_ENABLED or not untrusted_hosts:
        return

    try:
        message = EmailMessage()
        message['Subject'] = "[ALERT] Untrusted SSL Authority"
        message['From'] = EMAIL_FROM
        message['To'] = EMAIL_TO

        body = (
    "An automatic Vulnerability Management SSL Checker has identified a host "
    "under the organization that does not have a verified trusted authority "
    "for its SSL certificate being served.\n\n"
    "Please review the following hosts and ensure they comply with verified trusted "
    "SSL Certificate Authorities.\n\n"
)

       
        for host, issuer in untrusted_hosts.items():
            body += host + " (Issuer: " + issuer + ")\n"

        message.set_content(body)

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(message)

        print("Email notification sent.")
        logging.info("Email notification sent.")
    except Exception as e:
        print("Failed to send email: " + str(e))
        logging.error("Failed to send email: " + str(e))

def setup_logging():
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = "SSL_result_" + timestamp + ".log"
    logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(message)s')
    print("Logging to file: " + log_file)
    return log_file

def main():
    log_file = setup_logging()
    print("Starting SSL Authority Checker...")
    logging.info("Script started")

    hosts = read_hosts_from_csv("hosts.csv")
    all_serials = {}
    untrusted_hosts = {}

    for host in hosts:
        chain = get_certificate_chain(host)
        result = parse_certificate_chain(chain, host)
        if result:
            issuer, serials = result
            all_serials[host] = {
                "issuer": issuer,
                "serial_numbers": serials
            }
            if not is_trusted_authority(issuer):
                untrusted_hosts[host] = issuer

    save_serials(all_serials)
    send_email_notification(untrusted_hosts)
    print("SSL Authority Check complete. Log file: " + log_file)
    logging.info("Script completed")

if __name__ == "__main__":
    main()
