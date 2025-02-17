import re
import sys

def instrument_code(input_file, output_file):
    """
    Automates instrumentation of C code for KLEE symbolic execution.
    - Replaces fgets() and recv() calls with klee_make_symbolic.
    - Inserts klee_assert() for detected vulnerabilities.
    """

    with open(input_file, "r") as file:
        lines = file.readlines()

    instrumented_lines = []
    input_var = "data"
    inside_socket_read = False

    for line in lines:
        stripped = line.strip()

        # Detect and replace fgets()
        fgets_match = re.search(r'fgets\((\w+),\s*CHAR_ARRAY_SIZE,\s*stdin\)', stripped)
        if fgets_match:
            instrumented_lines.append(f'        klee_make_symbolic(&{input_var}, sizeof({input_var}), "{input_var}");')
            instrumented_lines.append(f'        // {stripped}  // Replaced by KLEE symbolic input')
            continue

        # Detect and replace recv() (socket read)
        if "recv(" in stripped:
            inside_socket_read = True
            instrumented_lines.append(f'        klee_make_symbolic(&{input_var}, sizeof({input_var}), "{input_var}");')
            instrumented_lines.append(f'        // {stripped}  // Replaced by KLEE symbolic input')
            continue

        # Close socket handling
        if inside_socket_read and "break;" in stripped:
            inside_socket_read = False
            continue

        # Insert KLEE assertion for buffer overflow check
        if "buffer[data] =" in stripped:
            instrumented_lines.append(f'            klee_assert(data >= 0 && data < (int)(sizeof(buffer) / sizeof(buffer[0])) && "Stack based buffer overflow check");')
            instrumented_lines.append(f'            // {stripped}  // Replaced by KLEE assertion')
            continue

        # Preserve original lines
        instrumented_lines.append(line)

    # Write the instrumented output
    with open(output_file, "w") as file:
        file.writelines(instrumented_lines)

    print(f"Instrumentation completed: {output_file}")

# Example usage
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python instrument_klee.py <input_file.c> <output_file.c>")
        sys.exit(1)

    instrument_code(sys.argv[1], sys.argv[2])
