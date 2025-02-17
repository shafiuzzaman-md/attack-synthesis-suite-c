#!/usr/bin/env python3

import os
import re


# Hardcoded input file paths (absolute or relative paths to STASE output .txt files)
INPUT_FILES = [
    "../stase_output/CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_01.txt",
    "../stase_output/CWE121_Stack_Based_Buffer_Overflow__CWE129_fscanf_01.txt"
]


def parse_stase_output(file_path: str):
    """
    Parse a single STASE output file to extract:
    - The base C filename (e.g., CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_01)
    - Simple lower/upper integer constraints for 'data'
    """
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # 1. Extract the base filename from the "KLEE: ERROR:" line
    match_file = re.search(r'instrumented_code/([^/\s]+)\.c:', content)
    if not match_file:
        raise ValueError(f"Could not extract filename from {file_path}")

    base_name = match_file.group(1)

    # 2. Extract simple constraints from "Preconditions" and "Postconditions"
    min_val = None
    max_val = None

    # Search for "data >= 0"
    if re.search(r'data\s*>=\s*0', content):
        min_val = 0

    # Search for "data < 10" or equivalent
    if re.search(r'data\s*<\s*(?:10|\(int\)\(sizeof\(buffer\))', content):
        max_val = 10

    return base_name, min_val, max_val


def generate_effect_code(base_name: str, min_val, max_val):
    """
    Generate the Python code for the instantiated CWE121 effect function.
    """
    function_name = f"{base_name}_bad"

    code = f"""from memorymodel.memory_model import MemoryState, Permissions, UserMode
from memorymodel.config import WORD_SIZE

class SegmentIdentifier:
    def __init__(self, segment_name: str):
        self.segment_name = segment_name

def {function_name}(
    memory: MemoryState,
    memory_segment: SegmentIdentifier,
    required_permissions: Permissions,
    stack_variable_address: int,
    control_data_offset: int,
    data: int,
    user_mode: UserMode
) -> MemoryState:
    \"\"\"
    Instantiated effect function for {base_name}.c
    \"\"\"

    # 1. Memory constraints
    if memory_segment.segment_name != "Stack Segment":
        raise ValueError("CWE121: Not in stack segment")

    if required_permissions.r != 1 or required_permissions.w != 1:
        raise PermissionError("CWE121: Required rw- permissions not met")
"""

    # Insert STASE-based constraints
    if min_val is not None:
        code += f"""
    # data >= {min_val}
    if data < {min_val}:
        return memory
"""
    if max_val is not None:
        code += f"""
    # data < {max_val}
    if data < {max_val}:
        return memory
"""

    # Overflow logic
    code += r"""
    # Check overflow reachability
    if (data - 10) < control_data_offset:
        raise ValueError("CWE121: Overflow cannot reach control data")

    control_data_address = stack_variable_address + 10 + control_data_offset

    if control_data_address < (stack_variable_address + data):
        element_size = WORD_SIZE // 8
        value_bytes = (1).to_bytes(element_size, byteorder='little', signed=True)
        memory = memory.memory_write(stack_variable_address, value_bytes, user_mode)

    return memory
"""

    return code


def process_stase_file(input_path: str):
    """
    Process a single STASE output file and generate the corresponding effect file.
    """
    base_name, min_val, max_val = parse_stase_output(input_path)
    effect_code = generate_effect_code(base_name, min_val, max_val)

    output_file_path = f"{base_name}_effect.py"
    with open(output_file_path, "w", encoding="utf-8") as f:
        f.write(effect_code)

    print(f"[Generated] {output_file_path}")


def main():
    for input_path in INPUT_FILES:
        try:
            process_stase_file(input_path)
        except Exception as e:
            print(f"[ERROR] Failed to process {input_path}: {e}")


if __name__ == "__main__":
    main()
