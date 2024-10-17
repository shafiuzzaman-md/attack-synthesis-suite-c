import os
import re

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

source_dir = 'klee-last'
parent_dir = os.path.abspath(os.path.join(source_dir, os.pardir))
postcondition_file = 'staseOutput.txt'
stase_output_path = os.path.join(parent_dir, postcondition_file)

# Check if the staseOutput.txt exists before proceeding
if not os.path.exists(stase_output_path):
    print(f"Error: The file {postcondition_file} does not exist.")
    exit(1)  # Exit the script with an error code

files = os.listdir(source_dir)

for file in files:
    if file.endswith('.assert.err'):
        base = file[:-11]
        assert_err_path = os.path.join(source_dir, f"{base}.assert.err")
        kquery_path = os.path.join(source_dir, f"{base}.kquery")
        folder_name = None

        if os.path.exists(assert_err_path):
            with open(assert_err_path, 'r') as err_file:
                for line in err_file:
                    if line.startswith("File:"):
                        match = re.search(r'File: .*\/(.*?)\.c', line)
                        if match:
                            folder_name = match.group(1)
                            break

        if folder_name:
            new_folder_path = os.path.join(parent_dir, folder_name)
            os.makedirs(new_folder_path, exist_ok=True)
            combined_file_path = os.path.join(new_folder_path, "signature.txt")

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

            print(f"Files have been combined and saved successfully in {folder_name}/signature.txt")
