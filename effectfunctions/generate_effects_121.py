#!/usr/bin/env python3

import re


INPUT_FILES = [
    "../stase_output/CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_01.txt",
    "../stase_output/CWE121_Stack_Based_Buffer_Overflow__CWE129_fscanf_01.txt",
    "../stase_output/CWE121_Stack_Based_Buffer_Overflow__CWE129_large_01.txt",
    "../stase_output/CWE121_Stack_Based_Buffer_Overflow__CWE129_rand_01.txt",
]


def parse_stase_output(file_path: str):
    """
    Parse STASE output file to extract:
    - base C filename
    - min_vals (list of lower bounds `data >= min_val`)
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
        return base_name, [], None

    min_vals = []
    max_val = None

    # Sle 0 X -> data >= 0 (handles Read int32 data cases)
    if re.search(r'Sle 0 .*?data', content):
        min_vals.append(0)

    # Handle Eq FALSE (Slt X 10) -> data >= 10
    negated_max_match = re.search(r'Eq FALSE \(Slt [^)]+ (\d+)\)', content)
    if negated_max_match:
        negated_min_val = int(negated_max_match.group(1))
        min_vals.append(negated_min_val)

    # Regular Slt data X -> data < X (some STASE outputs use this)
    max_match = re.search(r'Slt .*?data.*?(\d+)', content)
    if max_match:
        max_val = int(max_match.group(1))

    # Remove duplicates and sort min_vals for better readability
    min_vals = sorted(set(min_vals))
    #print(max_val)
    return base_name, min_vals, max_val


def generate_effect_code(base_name: str, min_vals, max_val):
    function_name = f"{base_name}_bad"
    print(max_val)
    # If max_val is available, use it as a hardcoded value in the overflow check
    if max_val is not None:
        buffer_size_param = ""
        buffer_size_value = str(max_val)
    else:
        buffer_size_param = "buffer_size: int, "
        buffer_size_value = "buffer_size"
    #print(buffer_size_param)
    # Ensure signature is clean if buffer_size_param is empty
    buffer_size_signature_part = buffer_size_param if buffer_size_param else ""

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
    {buffer_size_signature_part}
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
    if min_vals or max_val is not None:
        code += """
    # STASE constraints"""
        for min_val in min_vals:
            code += f"""
    if data < {min_val}:
        return memory"""

        if max_val is not None:
            code += f"""
    if data >= {max_val}:
        return memory"""

    code += f"""

    # STASE+Memory Model constraints
    if (data - {buffer_size_value}) < control_data_offset:
        raise ValueError("CWE121: Overflow cannot reach control data")

    control_data_address = stack_variable_address + {buffer_size_value} + control_data_offset

    if control_data_address < (stack_variable_address + data):
        element_size = WORD_SIZE // 8  
        value_bytes = (1).to_bytes(element_size, byteorder='little', signed=True)
        memory = memory.memory_write(stack_variable_address, value_bytes, user_mode)

    return memory
"""

    return code


def process_stase_file(input_path: str):
    base_name, min_vals, max_val = parse_stase_output(input_path)
    effect_code = generate_effect_code(base_name, min_vals, max_val)

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
