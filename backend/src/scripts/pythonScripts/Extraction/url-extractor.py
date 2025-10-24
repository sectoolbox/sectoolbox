# TITLE: URL Extractor
# DESCRIPTION: Extract all URLs from file (http, https, ftp)
# CATEGORY: Extraction
# AUTHOR: Sectoolbox

import re

file_path = 'sample.bin'

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    # Try to decode as text
    text = data.decode('utf-8', errors='ignore')

    # Regex pattern for URLs
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+|ftp://[^\s<>"{}|\\^`\[\]]+'

    urls = re.findall(url_pattern, text)

    print(f"File: {file_path}")
    print(f"Size: {len(data)} bytes")
    print(f"\n=== Extracted URLs ({len(urls)}) ===")

    if urls:
        # Remove duplicates while preserving order
        seen = set()
        unique_urls = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)

        for i, url in enumerate(unique_urls, 1):
            print(f"{i}. {url}")
    else:
        print("No URLs found in file")

except FileNotFoundError:
    print("Error: Please upload a file first!")
except Exception as e:
    print(f"Error: {e}")
