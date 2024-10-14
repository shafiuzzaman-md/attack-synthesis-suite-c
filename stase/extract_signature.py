import os
import re

def simplify_smt_expressions(text):
    # Simplify array definitions
    text = re.sub(r'array (\w+)\[\d+\] : w32 -> w8 = symbolic', r'\1 : int32 = symbolic', text)

    # Simplify SMT queries
    def simplify_query(match):
        variable_name = match.group(1)
        return f"Read int32 {variable_name}"

    # Replace ReadLSB with Read and adjust variable name formatting
    text = re.sub(r'\(ReadLSB w32 0 (\w+)\)', simplify_query, text)
    text = text.replace('false', 'FALSE')

    return text

# Define the source directory
source_dir = 'klee-last'
parent_dir = os.path.abspath(os.path.join(source_dir, os.pardir))

# List all files in the source directory
files = os.listdir(source_dir)

# Filter and process only files with the 'assert.err' extension
for file in files:
    if file.endswith('.assert.err'):
        base = file[:-11]  # Remove the '.assert.err' part to get the base name

        # Define the full paths for the original files
        assert_err_path = os.path.join(source_dir, f"{base}.assert.err")
        kquery_path = os.path.join(source_dir, f"{base}.kquery")

        # Read the .assert.err file to determine the folder name
        folder_name = None
        if os.path.exists(assert_err_path):
            with open(assert_err_path, 'r') as file:
                for line in file:
                    if line.startswith("File:"):
                        match = re.search(r'File: .*\/(.*?)\.c', line)
                        if match:
                            folder_name = match.group(1)
                            break

        if folder_name:
            # Create a new directory with the name extracted from the .assert.err file
            new_folder_path = os.path.join(parent_dir, folder_name)
            if not os.path.exists(new_folder_path):
                os.makedirs(new_folder_path)

            # Define destination path for the combined file
            combined_file_path = os.path.join(new_folder_path, "signature.txt")

            # Combine and write the content of '.kquery' and '.assert.err' to a single file
            with open(combined_file_path, 'w') as combined_file:
                if os.path.exists(kquery_path):
                    with open(kquery_path, 'r') as kquery_file:
                        preconditions_text = kquery_file.read()
                        simplified_text = simplify_smt_expressions(preconditions_text)
                        combined_file.write("Preconditions:\n")
                        combined_file.write(simplified_text + "\n")
                if os.path.exists(assert_err_path):
                    with open(assert_err_path, 'r') as assert_err_file:
                        combined_file.write("Postconditions:\n")
                        combined_file.write(assert_err_file.read() + "\n")

            print(f"Files have been combined and saved successfully in {folder_name}/signature.txt")
