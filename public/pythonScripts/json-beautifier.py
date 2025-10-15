# TITLE: ✨ JSON Beautifier
# DESCRIPTION: Parse and prettify JSON data
# CATEGORY: Data Processing
# AUTHOR: Sectoolbox

import json

file_path = '/uploads/data.json'

try:
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    print("=== JSON Beautifier ===")
    print(f"File: {file_path}\n")

    # Pretty print with indentation
    pretty_json = json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True)

    print(pretty_json)

    # Statistics
    print("\n=== Statistics ===")

    def count_structure(obj, depth=0):
        stats = {'objects': 0, 'arrays': 0, 'strings': 0, 'numbers': 0, 'booleans': 0, 'nulls': 0, 'max_depth': depth}

        if isinstance(obj, dict):
            stats['objects'] += 1
            for value in obj.values():
                sub_stats = count_structure(value, depth + 1)
                for key in sub_stats:
                    if key == 'max_depth':
                        stats['max_depth'] = max(stats['max_depth'], sub_stats['max_depth'])
                    else:
                        stats[key] += sub_stats[key]
        elif isinstance(obj, list):
            stats['arrays'] += 1
            for item in obj:
                sub_stats = count_structure(item, depth + 1)
                for key in sub_stats:
                    if key == 'max_depth':
                        stats['max_depth'] = max(stats['max_depth'], sub_stats['max_depth'])
                    else:
                        stats[key] += sub_stats[key]
        elif isinstance(obj, str):
            stats['strings'] += 1
        elif isinstance(obj, (int, float)):
            stats['numbers'] += 1
        elif isinstance(obj, bool):
            stats['booleans'] += 1
        elif obj is None:
            stats['nulls'] += 1

        return stats

    stats = count_structure(data)
    print(f"Objects:  {stats['objects']}")
    print(f"Arrays:   {stats['arrays']}")
    print(f"Strings:  {stats['strings']}")
    print(f"Numbers:  {stats['numbers']}")
    print(f"Booleans: {stats['booleans']}")
    print(f"Nulls:    {stats['nulls']}")
    print(f"Max Nesting Depth: {stats['max_depth']}")

except json.JSONDecodeError as e:
    print(f"❌ JSON Parse Error: {e}")
except FileNotFoundError:
    print("❌ Error: Please upload a file first!")
except Exception as e:
    print(f"❌ Error: {e}")
