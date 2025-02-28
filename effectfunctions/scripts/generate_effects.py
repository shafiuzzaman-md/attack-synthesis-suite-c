#!/usr/bin/env python3

import os
import re
import sys

###############################################################################
# Configuration: Where are the templates, output directory, and STASE output?
###############################################################################

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

TEMPLATES_DIR = os.path.join(SCRIPT_DIR, "../templates")
EFFECTS_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))

# Points to ../../stase_output relative to where this script is
STASE_OUTPUT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "../../stase_output"))

# Template source files for various CWE cases
template_files = {
    "CWE121": os.path.join(TEMPLATES_DIR, "cwe121_effect.py"),
    "CWE122": os.path.join(TEMPLATES_DIR, "cwe122_effect.py"),
    "CWE126": os.path.join(TEMPLATES_DIR, "cwe126_effect.py"),
    "CWE127": os.path.join(TEMPLATES_DIR, "cwe127_effect.py"),
}

###############################################################################
# Function to Parse STASE Constraints
###############################################################################
def parse_stase_constraints(signature_path):
    """Extracts and formats STASE constraints dynamically from a signature file."""
    with open(signature_path, "r") as file:
        lines = file.readlines()

    preconditions = []
    collecting = False

    for line in lines:
        line = line.strip()
        if "Preconditions:" in line:
            collecting = True
            continue
        elif "Postconditions:" in line:
            break  # Stop at postconditions

        if collecting and line:
            preconditions.append(line)

    if not preconditions:
        return ""

    parsed_constraints = []
    
    for cond in preconditions:
        # Extract variable name dynamically
        match = re.search(r'(\w+):Read int32 (\w+)', cond)
        variable = match.group(2) if match else "data"

        # Extract numeric bounds dynamically
        num_match = re.findall(r'(\d+)', cond)
        num_values = [int(n) for n in num_match] if num_match else []

        if "Sle" in cond and num_values:  # Signed less-than or equal to (≤)
            parsed_constraints.append(f"{variable} >= {num_values[0]}")
        elif "Slt" in cond and num_values:  # Signed less-than (<)
            parsed_constraints.append(f"{variable} < {num_values[0]}")
        elif "Eq FALSE" in cond:  # Negated equality condition
            match = re.search(r'Eq FALSE \(Slt (\w+) (\d+)\)', cond)
            if match:
                parsed_constraints.append(f"{match.group(1)} >= {match.group(2)}")

    if parsed_constraints:
        return f"    # ✅ STASE Constraint: {' OR '.join(parsed_constraints)} must hold\n" + \
               f"    if {' or '.join(parsed_constraints)}:\n" + \
               f"        return 0  # 🚨 Prevents invalid buffer access\n"
    return ""

###############################################################################
# Main Script Logic
###############################################################################
def main():
    if len(sys.argv) != 2:
        print("Usage: python generate_effects.py <signature_directory/signature_filename>")
        sys.exit(1)

    signature_filename = os.path.basename(sys.argv[1])  # Extract filename
    signature_file_path = os.path.join(STASE_OUTPUT_DIR, signature_filename)

    if not os.path.exists(signature_file_path):
        print(f"[ERROR] File not found: {signature_file_path}")
        sys.exit(1)

    # Derive base_name and CWE type
    base_name = os.path.splitext(signature_filename)[0]
    cwe_type = base_name.split("_")[0]  # Extract CWE type (e.g., "CWE126")

    # Pick the correct template file
    source_file = template_files.get(cwe_type)
    if not source_file or not os.path.exists(source_file):
        print(f"[ERROR] No template found for {cwe_type}")
        sys.exit(1)

    destination_file = os.path.join(EFFECTS_DIR, f"{base_name}_effect.py")

    # Ensure the destination directory exists
    os.makedirs(EFFECTS_DIR, exist_ok=True)

    # Read the template content
    with open(source_file, "r") as f:
        content = f.read()

    # Extract original function name dynamically
    match = re.search(r"def\s+(CWE\d+_[a-zA-Z0-9_]+)", content)
    if match:
        original_function = match.group(1)
        new_function_name = base_name + "_bad"
        updated_content = content.replace(f"def {original_function}", f"def {new_function_name}")
    else:
        print(f"[WARNING] No function definition found in {source_file}")
        sys.exit(1)

    # Parse STASE constraints from the signature file
    stase_constraints = parse_stase_constraints(signature_file_path)

    # Insert STASE constraints into the effect function
    pattern = rf"(def\s+{new_function_name}.*?\):\s*\n)(\s+\"\"\"[^\"]*\"\"\"\s*\n)?"
    insertion_point = re.search(pattern, updated_content, re.DOTALL)
    if insertion_point:
        start_of_body_index = insertion_point.end()
        updated_content = (
            updated_content[:start_of_body_index]
            + f"\n    {stase_constraints}"
            + updated_content[start_of_body_index:]
        )
    else:
        # Fallback if docstring not found
        pattern2 = rf"(def\s+{new_function_name}.*?\):\s*\n)"
        updated_content = re.sub(pattern2, rf"\1    {stase_constraints}\n", updated_content)

    # Write final content to the new effect file
    with open(destination_file, "w") as f:
        f.write(updated_content)

    print(f"[SUCCESS] File '{destination_file}' has been created successfully with STASE constraints inserted.")

if __name__ == "__main__":
    main()
