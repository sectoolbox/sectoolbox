# simple_strings.py
import re

file_path = '/uploads/sample.bin'

with open(file_path, 'rb') as f:
    data = f.read()

# printable ASCII sequences (space to ~), length ≥ 4
for m in re.finditer(rb'[ -~]{4,}', data):
    print(m.group().decode('utf-8', errors='ignore'))
