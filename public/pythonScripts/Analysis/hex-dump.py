# TITLE: Hex Dump Viewer
# DESCRIPTION: Display full hexadecimal dump with ASCII representation
# CATEGORY: Analysis
# AUTHOR: Sectoolbox

file_path = 'sample.bin'

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    print(f"File: {file_path}")
    print(f"Size: {len(data)} bytes")
    print("\n=== Hex Dump ===")

    for offset in range(0, len(data), 16):
        chunk = data[offset:offset+16]

        # Hex representation
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        hex_part = hex_part.ljust(47)

        # ASCII representation
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)

        print(f"{offset:08x}  {hex_part}  |{ascii_part}|")

    print(f"{len(data):08x}")

except FileNotFoundError:
    print("Error: Please upload a file first!")
except Exception as e:
    print(f"Error: {e}")
