# TITLE: 🔎 String Extractor
# DESCRIPTION: Extract printable strings from binary files
# CATEGORY: File Analysis
# AUTHOR: Sectoolbox

import re

def extract_strings(data, min_length=4):
    """Extract printable ASCII strings"""
    # ASCII strings
    ascii_pattern = rb'[ -~]{' + str(min_length).encode() + rb',}'
    ascii_strings = re.findall(ascii_pattern, data)

    # Unicode strings (UTF-16 LE)
    unicode_pattern = rb'(?:[ -~]\x00){' + str(min_length).encode() + rb',}'
    unicode_strings = re.findall(unicode_pattern, data)

    return ascii_strings, unicode_strings

# Upload your file first
file_path = '/uploads/sample.bin'
min_length = 6

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    print(f"=== String Extractor (min length: {min_length}) ===")
    print(f"File: {file_path}\n")

    ascii_strings, unicode_strings = extract_strings(data, min_length)

    # Display ASCII strings
    print(f"📝 ASCII Strings Found: {len(ascii_strings)}")
    print("-" * 50)
    for i, s in enumerate(ascii_strings[:50]):  # First 50
        try:
            decoded = s.decode('ascii', errors='ignore')
            print(f"{i+1:3}. {decoded}")
        except:
            pass

    if len(ascii_strings) > 50:
        print(f"\n... and {len(ascii_strings) - 50} more")

    # Display Unicode strings (sample)
    if unicode_strings:
        print(f"\n🔤 Unicode Strings Found: {len(unicode_strings)}")
        print("-" * 50)
        for i, s in enumerate(unicode_strings[:20]):  # First 20
            try:
                decoded = s.decode('utf-16le', errors='ignore')
                print(f"{i+1:3}. {decoded}")
            except:
                pass

    # Find interesting patterns
    print("\n🔍 Interesting Patterns:")
    text = data.decode('ascii', errors='ignore')

    urls = re.findall(r'https?://[^\s<>"{}|\\^[\]\']+', text)
    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)

    if urls:
        print(f"  🌐 URLs: {len(urls)}")
        for url in urls[:5]:
            print(f"     {url}")

    if emails:
        print(f"  📧 Emails: {len(emails)}")
        for email in emails[:5]:
            print(f"     {email}")

    if ips:
        print(f"  🖧  IPs: {len(set(ips))}")
        for ip in list(set(ips))[:5]:
            print(f"     {ip}")

except FileNotFoundError:
    print("❌ Error: Please upload a file first!")
except Exception as e:
    print(f"❌ Error: {e}")
