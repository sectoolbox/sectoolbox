# TITLE: IP Address Extractor
# DESCRIPTION: Extract IPv4 and IPv6 addresses from file
# CATEGORY: Extraction
# AUTHOR: Sectoolbox

import re

file_path = 'sample.bin'

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    # Try to decode as text
    text = data.decode('utf-8', errors='ignore')

    # IPv4 pattern
    ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'

    # IPv6 pattern (simplified)
    ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b'

    ipv4_addresses = re.findall(ipv4_pattern, text)
    ipv6_addresses = re.findall(ipv6_pattern, text)

    print(f"File: {file_path}")
    print(f"Size: {len(data)} bytes")

    print(f"\n=== IPv4 Addresses ({len(ipv4_addresses)}) ===")
    if ipv4_addresses:
        # Remove duplicates while preserving order
        seen = set()
        unique_ipv4 = []
        for ip in ipv4_addresses:
            if ip not in seen:
                seen.add(ip)
                unique_ipv4.append(ip)

        for i, ip in enumerate(unique_ipv4, 1):
            # Classify IP address type
            octets = list(map(int, ip.split('.')))
            if octets[0] == 10:
                ip_type = "(Private Class A)"
            elif octets[0] == 172 and 16 <= octets[1] <= 31:
                ip_type = "(Private Class B)"
            elif octets[0] == 192 and octets[1] == 168:
                ip_type = "(Private Class C)"
            elif octets[0] == 127:
                ip_type = "(Loopback)"
            elif octets[0] >= 224:
                ip_type = "(Multicast/Reserved)"
            else:
                ip_type = "(Public)"

            print(f"{i}. {ip} {ip_type}")
    else:
        print("No IPv4 addresses found")

    print(f"\n=== IPv6 Addresses ({len(ipv6_addresses)}) ===")
    if ipv6_addresses:
        seen = set()
        unique_ipv6 = []
        for ip in ipv6_addresses:
            if ip not in seen:
                seen.add(ip)
                unique_ipv6.append(ip)

        for i, ip in enumerate(unique_ipv6, 1):
            print(f"{i}. {ip}")
    else:
        print("No IPv6 addresses found")

except FileNotFoundError:
    print("Error: Please upload a file first!")
except Exception as e:
    print(f"Error: {e}")
