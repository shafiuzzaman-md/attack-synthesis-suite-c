import os
import re

def simplify_smt_expressions(text):
    text = re.sub(r'array (\w+)\[\d+\] : w32 -> w8 = symbolic', r'\1 : int32 = symbolic', text)
    text = re.sub(r'\(ReadLSB w32 0 (\w+)\)', r'Read int32 \1', text)
    text = text.replace('false', 'FALSE')
    return text

source_dir = 'klee-last'
parent_dir = os.path.abspath(os.path.join(source_dir, os.pardir))
postcondition_file = 'staseOutput.txt'
stase_output_path = os.path.join(parent_dir, postcondition_file)

# Check if the staseOutput.txt exists before proceeding
if not os.path.exists(stase_output_path):
    print(f"Error: The file {stase_output_path} does not exist.")
    exit(1)  # Exit the script with an error code

files = os.listdir(source_dir)

for file in files:
    if file.endswith('.assert.err'):
        base = file[:-11]
        assert_err_path = os.path.join(source_dir, f"{base}.assert.err")
        kquery_path = os.path.join(source_dir, f"{base}.kquery")
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
            new_folder_path = os.path.join(parent_dir, folder_name)
            os.makedirs(new_folder_path, exist_ok=True)
            combined_file_path = os.path.join(new_folder_path, "signature.txt")

            with open(combined_file_path, 'w+') as combined_file:
                if os.path.exists(kquery_path):
                    with open(kquery_path, 'r') as kquery_file:
                        combined_file.write("Preconditions:\n")
                        combined_file.write(simplify_smt_expressions(kquery_file.read()) + "\n")

                with open(stase_output_path, 'r') as postcondition_file:
                    content = postcondition_file.readlines()
                    for line in content:
                        if "ASSERTION FAIL:" in line:
                            combined_file.write("Postconditions:\n")
                            combined_file.write(line)
                            args = re.findall(r'\b\w+\b', line.split("ASSERTION FAIL:")[1])
                            for arg in args:
                                pattern = re.compile(rf"\b{arg}\b:")
                                for content_line in content:
                                    if pattern.search(content_line) and content_line.strip() != line.strip():
                                        combined_file.write(content_line)

                # Re-read, simplify, and overwrite the content
                combined_file.seek(0)
                full_text = combined_file.read()
                combined_file.seek(0)
                combined_file.truncate()
                combined_file.write(simplify_smt_expressions(full_text))

            print(f"Files have been combined and saved successfully in {folder_name}/signature.txt")
