#!/usr/bin/env python3

import os
import re


INPUT_FILES = [
    "../stase_output/CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_01.txt",
    "../stase_output/CWE121_Stack_Based_Buffer_Overflow__CWE129_large_01.txt",
]


def parse_stase_output(file_path: str):
    """
    Parse STASE output file to extract:
    - base C filename
    - min_val (for `data >= min_val`)
    - max_val (for `data < max_val`)
    """
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    match_file = re.search(r'instrumented_code/([^/\s]+)\.c:', content)
    if not match_file:
        raise ValueError(f"Could not extract filename from {file_path}")
    base_name = match_file.group(1)

    # Empty preconditions: no constraints, trigger unconditionally
    if re.search(r'Preconditions:\s*\(query\s*\[\]\s*FALSE\)', content):
        return base_name, None, None

    min_val = None
    max_val = None

    if re.search(r'Sle 0.*data', content):
        min_val = 0

    max_match = re.search(r'Slt .*data.*?(\d+)', content)
    if max_match:
        max_val = int(max_match.group(1))

    return base_name, min_val, max_val


def generate_effect_code(base_name: str, min_val, max_val):
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

    # Memory constraints
    if memory_segment.segment_name != "Stack Segment":
        raise ValueError("CWE121: Not in stack segment")

    if required_permissions.r != 1 or required_permissions.w != 1:
        raise PermissionError("CWE121: Required rw- permissions not met")
"""

    # Add STASE constraints block if there are any
    if min_val is not None or max_val is not None:
        code += """
    # STASE constraints"""
        if min_val is not None:
            code += f"""
    if data < {min_val}:
        return memory"""
        if max_val is not None:
            code += f"""
    if data < {max_val}:
        return memory"""

    # Add overflow check with max_val as buffer size if available, or default 10 otherwise
    buffer_size_for_effect = max_val if max_val is not None else 10

    code += f"""

    # STASE+Memory Model constraints
    if (data - {buffer_size_for_effect}) < control_data_offset:
        raise ValueError("CWE121: Overflow cannot reach control data")

    control_data_address = stack_variable_address + {buffer_size_for_effect} + control_data_offset

    if control_data_address < (stack_variable_address + data):
        element_size = WORD_SIZE // 8  
        value_bytes = (1).to_bytes(element_size, byteorder='little', signed=True)
        memory = memory.memory_write(stack_variable_address, value_bytes, user_mode)

    return memory
"""

    return code


def process_stase_file(input_path: str):
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
