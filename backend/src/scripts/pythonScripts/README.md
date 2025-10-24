# Python Forensics Scripts

This folder contains Python scripts that are dynamically loaded in the Python Forensics Environment.

## Folder Structure

Scripts are organized into category folders for better organization:

```
/pythonScripts/
├── Analysis/       - File analysis scripts (hashing, signatures, etc.)
├── Extraction/     - Data extraction scripts (strings, metadata, etc.)
├── Forensics/      - Forensic analysis scripts (memory, disk, etc.)
├── Decoding/       - Encoding/decoding scripts (base64, hex, etc.)
└── README.md
```

## How to Add New Scripts

Simply add a new `.py` file to a category folder - it will be automatically discovered and loaded!

**Option 1: Use folder-based categories**
1. Place your script in the appropriate category folder (e.g., `Analysis/my-script.py`)
2. The category is automatically determined from the folder name
3. No metadata comments required (but still recommended for descriptions)

**Option 2: Use metadata comments**
1. Add metadata comments at the top of your script:

```python
# TITLE: Your Script Title
# DESCRIPTION: Brief description of what the script does
# CATEGORY: Custom Category (overrides folder category)
# AUTHOR: Your Name

# Your Python code here...
```

Scripts are automatically discovered at build time using Vite's `import.meta.glob` feature with recursive subfolder support.

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

```
/Extraction/
└── string-extractor.py - Extract ASCII/Unicode strings
```

All `.py` files in category folders are automatically loaded - no manual list maintenance required!

## Removing Scripts

To remove a script:
1. Simply delete the `.py` file from this folder
2. That's it! The script will no longer be loaded (automatic discovery)

## Dependencies

Scripts can use any Python standard library modules.
For external packages, users can install them via the "Install Package" card in the UI.
