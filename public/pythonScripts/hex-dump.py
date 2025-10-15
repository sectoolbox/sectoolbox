# TITLE: 📄 Hex Dump Viewer
# DESCRIPTION: Display file contents in hexadecimal format
# CATEGORY: File Analysis
# AUTHOR: Sectoolbox

def hex_dump(data, offset=0, length=256):
    """Generate hex dump similar to xxd"""
    lines = []
    for i in range(0, min(len(data), length), 16):
        # Offset
        line = f"{offset + i:08x}  "

        # Hex bytes
        hex_part = ""
        ascii_part = ""
        for j in range(16):
            if i + j < len(data):
                byte = data[i + j]
                hex_part += f"{byte:02x} "
                ascii_part += chr(byte) if 32 <= byte < 127 else "."
            else:
                hex_part += "   "
                ascii_part += " "

            # Add extra space in middle
            if j == 7:
                hex_part += " "

        line += hex_part + " |" + ascii_part + "|"
        lines.append(line)

    return "\n".join(lines)

# Upload your file first
file_path = '/uploads/sample.bin'
display_bytes = 512  # Show first 512 bytes

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    print("=== Hex Dump Viewer ===")
    print(f"File: {file_path}")
    print(f"Size: {len(data):,} bytes")
    print(f"Showing: first {min(display_bytes, len(data))} bytes\n")

    print(hex_dump(data, length=display_bytes))

    if len(data) > display_bytes:
        print(f"\n... and {len(data) - display_bytes:,} more bytes")

except FileNotFoundError:
    print("❌ Error: Please upload a file first!")
except Exception as e:
    print(f"❌ Error: {e}")
