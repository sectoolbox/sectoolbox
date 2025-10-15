# TITLE: Email Extractor
# DESCRIPTION: Extract all email addresses from file
# CATEGORY: Extraction
# AUTHOR: Sectoolbox

import re

file_path = 'sample.bin'

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    # Try to decode as text
    text = data.decode('utf-8', errors='ignore')

    # Regex pattern for email addresses
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

    emails = re.findall(email_pattern, text)

    print(f"File: {file_path}")
    print(f"Size: {len(data)} bytes")
    print(f"\n=== Extracted Email Addresses ({len(emails)}) ===")

    if emails:
        # Remove duplicates while preserving order
        seen = set()
        unique_emails = []
        for email in emails:
            email_lower = email.lower()
            if email_lower not in seen:
                seen.add(email_lower)
                unique_emails.append(email)

        for i, email in enumerate(unique_emails, 1):
            print(f"{i}. {email}")

        # Group by domain
        domains = {}
        for email in unique_emails:
            domain = email.split('@')[1]
            if domain not in domains:
                domains[domain] = []
            domains[domain].append(email)

        print(f"\n=== By Domain ({len(domains)}) ===")
        for domain, addrs in sorted(domains.items()):
            print(f"\n{domain}:")
            for addr in addrs:
                print(f"  - {addr}")
    else:
        print("No email addresses found in file")

except FileNotFoundError:
    print("Error: Please upload a file first!")
except Exception as e:
    print(f"Error: {e}")
