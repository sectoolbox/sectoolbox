# Python Forensics Scripts

This folder contains Python scripts that are dynamically loaded in the Python Forensics Environment.

## How to Add New Scripts

Simply add a new `.py` file to this folder - it will be automatically discovered and loaded!

1. Create a new `.py` file in this folder
2. Add metadata comments at the top (optional but recommended):

```python
# TITLE: Your Script Title
# DESCRIPTION: Brief description of what the script does
# CATEGORY: File Analysis | Malware Analysis | Decoding | Archive Analysis | Data Processing
# AUTHOR: Your Name

# Your Python code here...
```

3. The script will automatically appear in the Examples dropdown - no code changes needed!

Scripts are automatically discovered at build time using Vite's `import.meta.glob` feature.

## Metadata Fields

- **TITLE**: Display name in the UI (can include emoji)
- **DESCRIPTION**: Short description of functionality
- **CATEGORY**: Groups scripts in the dropdown
- **AUTHOR**: Creator name

## File Naming Convention

Use lowercase with hyphens: `my-script-name.py`

## Default Filename

All scripts should use `/uploads/sample.bin` as the default file path.
This will be automatically replaced with the user's uploaded filename.

## Example Script

```python
# TITLE: 🔍 My Analyzer
# DESCRIPTION: Analyzes files and extracts data
# CATEGORY: File Analysis
# AUTHOR: Sectoolbox

import hashlib

file_path = '/uploads/sample.bin'

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    # Your analysis code here
    print(f"Analyzing: {file_path}")
    print(f"Size: {len(data)} bytes")

except FileNotFoundError:
    print("❌ Error: Please upload a file first!")
except Exception as e:
    print(f"❌ Error: {e}")
```

## Current Scripts

- string-extractor.py - Extract ASCII/Unicode strings

All `.py` files in this folder are automatically loaded - no manual list maintenance required!

## Removing Scripts

To remove a script:
1. Simply delete the `.py` file from this folder
2. That's it! The script will no longer be loaded (automatic discovery)

## Dependencies

Scripts can use any Python standard library modules.
For external packages, users can install them via the "Install Package" card in the UI.
