import shutil
import os
import re

# Define template source files
template_file1 = "../templates/cwe121_effect.py"
template_file2 = "../templates/cwe122_effect.py"

# Define input files
INPUT_FILES = [
  # "../stase_output/CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_01.txt",
 #  "../stase_output/CWE121_Stack_Based_Buffer_Overflow__CWE129_fscanf_01.txt",
 #  "../stase_output/CWE121_Stack_Based_Buffer_Overflow__CWE129_large_01.txt",
  # "../stase_output/CWE121_Stack_Based_Buffer_Overflow__CWE129_rand_01.txt",
  "../stase_output/CWE122_Heap_Based_Buffer_Overflow__CWE131_loop_01.txt"
]

OUTPUT_DIR = ".."

# Process each input file
for input_file in INPUT_FILES:
    base_name = os.path.splitext(os.path.basename(input_file))[0]
    source_file = template_file1 if "CWE121" in base_name else template_file2
    destination_file = os.path.join(OUTPUT_DIR, f"{base_name}_effect.py")
    
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
        print(f"No function definition found in {source_file}")
        continue
    
    # Write to the new file
    with open(destination_file, "w") as f:
        f.write(updated_content)
    
    print(f"File '{destination_file}' has been created successfully.")
