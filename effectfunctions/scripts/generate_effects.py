import os
import re
import sys

# Get the absolute path of the script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "templates"))
EFFECTS_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))

# Define available templates
TEMPLATE_PREFIXES = [f.split("_")[0].upper() for f in os.listdir(TEMPLATES_DIR) if f.endswith("_effect.py")]

# Ensure a file is passed as an argument
if len(sys.argv) != 2:
    print("Usage: python generate_effects.py <signature_file>")
    sys.exit(1)

# Read the input file
input_file = sys.argv[1]
base_name = os.path.splitext(os.path.basename(input_file))[0]

# Determine the correct template file dynamically
source_file = None
for prefix in TEMPLATE_PREFIXES:
    if prefix in base_name:
        source_file = os.path.join(TEMPLATES_DIR, f"{prefix.lower()}_effect.py")
        break

if source_file is None:
    print(f"[ERROR] No matching template found for {base_name}")
    sys.exit(1)

destination_file = os.path.join(EFFECTS_DIR, f"{base_name}_effect.py")

# Ensure the destination directory exists
os.makedirs(EFFECTS_DIR, exist_ok=True)

# Check if the template file exists
if not os.path.exists(source_file):
    print(f"[ERROR] Template file not found: {source_file}")
    sys.exit(1)

# Read the content of the source file
with open(source_file, "r") as f:
    content = f.read()

# Extract the original function name dynamically
match = re.search(r"def (CWE\d+_[a-zA-Z0-9_]+)", content)
if match:
    original_function = match.group(1)
    new_function_name = base_name + "_bad"
    updated_content = content.replace(f"def {original_function}", f"def {new_function_name}")
else:
    print(f"[WARNING] No function definition found in {source_file}")
    sys.exit(1)

# Write to the new file
with open(destination_file, "w") as f:
    f.write(updated_content)

print(f"[SUCCESS] File '{destination_file}' has been created successfully.")
