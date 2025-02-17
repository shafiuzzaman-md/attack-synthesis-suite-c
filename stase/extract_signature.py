import os
import re
import sys
import string

def simplify_smt_expressions(text):
    # Replace symbolic array declarations with int32 symbolic variables
    text = re.sub(r'array (\w+)\[\d+\] : w32 -> w8 = symbolic', r'\1 : int32 = symbolic', text)
    # Replace ReadLSB expressions with simplified Read expressions
    text = re.sub(r'\(ReadLSB w32 0 (\w+)\)', r'Read int32 \1', text)
    # Replace 'w64' with 'int64' for consistency
    text = text.replace('w64', 'int64')
    # Replace 'false' with 'FALSE' for consistency
    text = text.replace('false', 'FALSE')
    return text

def sanitize_for_filename(name):
    """
    Removes or replaces characters that are invalid for filenames.
    """
    # Define valid characters: letters, digits, '-', '_', '.', '(', ')', and space
    valid_chars = f"-_.() {string.ascii_letters}{string.digits}"
    # Replace invalid characters with underscores
    sanitized_name = ''.join(c if c in valid_chars else '_' for c in name)
    # Optionally, truncate the name to a reasonable length
    return sanitized_name[:100]  # Limit the length to 100 characters

if len(sys.argv) < 3:
        print("Usage: python3 extract_signature.py <source_file_path> <output_file_name>")
        exit(1)

postcondition_file = sys.argv[1]
output_file_name = sys.argv[2]
#base_name = os.path.splitext(os.path.basename(source_filename))[0]

source_dir = 'klee_output/klee-last'
parent_dir = os.path.abspath(os.path.join('klee-last', os.pardir))

#postcondition_file = f'{base_name}.txt'
stase_output_path = os.path.join(parent_dir, postcondition_file)

# Define the output base directory 'stase_output' outside of parent_dir
output_base_dir = os.path.abspath(os.path.join(parent_dir, os.pardir))
#print(output_base_dir)
# Create 'stase_output' directory if it doesn't exist
os.makedirs(output_base_dir, exist_ok=True)

# Check if the output file exists before proceeding
if not os.path.exists(stase_output_path):
    print(f"Error: The file {postcondition_file} does not exist.")
    exit(1)

files = os.listdir(source_dir)

for file in files:
    if file.endswith('.assert.err'):
        base = file[:-11]  # Remove '.assert.err' to get the base name
        assert_err_path = os.path.join(source_dir, f"{base}.assert.err")
        kquery_path = os.path.join(source_dir, f"{base}.kquery")
        folder_name = None

        # Extract the base name from the .assert.err file
        if os.path.exists(assert_err_path):
            with open(assert_err_path, 'r') as err_file:
                for line in err_file:
                    if line.startswith("File:"):
                        match = re.search(r'File: .*\/(.*?)\.c', line)
                        if match:
                            base_folder = match.group(1)
                            break

        if base_folder:
            # **Updated Folder Naming Logic Starts Here**

            # Extract the assertion name from the postcondition file
            assertion_name = None
            with open(stase_output_path, 'r') as post_file:
                for post_line in post_file:
                    if "ASSERTION FAIL:" in post_line:
                        # Example line:
                        # KLEE: ERROR: ./instrumented_code/SmmLegacy.c:58: ASSERTION FAIL: !StackIsExecutable
                        post_match = re.search(rf'{re.escape(base_folder)}\.c:\d+: ASSERTION FAIL: !?(\w+)', post_line)
                        if post_match:
                            assertion_name = post_match.group(1)
                            break  # Assuming one assertion per .assert.err file

            if assertion_name:
                # Sanitize the assertion name
                sanitized_assertion = sanitize_for_filename(assertion_name)
                # Combine base name and sanitized assertion name
                combined_folder_name = f"{base_folder}_{sanitized_assertion}"

                # **Removed Counter Logic**

                # Create the new folder inside 'stase_output' directory
                #new_folder_path = os.path.join(output_base_dir, combined_folder_name)
                #os.makedirs(new_folder_path, exist_ok=True)
                print(output_file_name)
                combined_file_path = os.path.join(output_base_dir, output_file_name)
            else:
                print(f"Warning: Assertion name not found for base '{base_folder}' in {postcondition_file}. Skipping folder creation.")
                continue  # Skip to the next file

            # **Updated Folder Naming Logic Ends Here**

            precondition_text = ''
            if os.path.exists(kquery_path):
                with open(kquery_path, 'r') as kquery_file:
                    original_precondition_text = kquery_file.read()
                    simplified_precondition_text = simplify_smt_expressions(original_precondition_text)
                    
                    # Prepare to collect comments for constructs
                    comments = []
                    # Check for constructs in the original preconditions
                    constructs = {
                        'SExt': "# SExt (Sign Extension) extends a smaller integer type to a larger integer type while preserving the sign.",
                        'ZExt': "# ZExt (Zero Extension) extends a smaller integer type to a larger integer type by adding zeros to the higher-order bits.",
                        'Slt':  "# Slt is a signed less-than comparison operator.",
                        'Eq':   "# Eq represents the equality operator.",
                        'Mul':  "# Mul represents the multiplication operator."
                    }
                    for construct, comment in constructs.items():
                        if construct in original_precondition_text:
                            comments.append(comment)
                    
                    precondition_text = "Preconditions:\n" + simplified_precondition_text + "\n"
                    if comments:
                        precondition_text += "\n" + "\n".join(comments) + "\n"

            postcondition_text = ''
            with open(stase_output_path, 'r') as postcondition_file_content:
                content = postcondition_file_content.readlines()
                for line in content:
                    if "ASSERTION FAIL:" in line:
                        postcondition_text += "Postconditions:\n"
                        postcondition_text += line
                        args = re.findall(r'\b\w+\b', line.split("ASSERTION FAIL:")[1])
                        for arg in args:
                            pattern = re.compile(rf"\b{arg}\b:")
                            for content_line in content:
                                if pattern.search(content_line) and content_line.strip() != line.strip():
                                    postcondition_text += content_line

            # Simplify postconditions
            postcondition_text = simplify_smt_expressions(postcondition_text)

            # Combine preconditions and postconditions
            full_text = precondition_text + "\n" + postcondition_text

            # Write the final content to the combined file
            with open(combined_file_path, 'w') as combined_file:
                combined_file.write(full_text)

            print(f"Files have been combined and saved successfully")
