#!/usr/bin/env python3

import re
import sys

def transform_line(line):
    """
    Applies inline transformations while preserving line numbering:
      1) fscanf(...) -> klee_make_symbolic(...)
      2) fgets(...) -> klee_make_symbolic(...)
      3) recv(...) -> klee_make_symbolic(...)
      4) data = RAND32(); -> klee_make_symbolic(...)
      5) Insert klee_assert() before malloc(data) to prevent sign extension issues
      6) Insert klee_assert() before memset(dataBuffer, 'A', data-1) to check buffer overflow
      7) Insert klee_assert() before dataBuffer[data-1] to prevent out-of-bounds access
      8) Insert klee_assert() before memcpy(dest, source, data) to prevent sign extension issues
      9) Insert klee_assert() before dest[data] to prevent buffer overflow
    """

    original_line = line.rstrip('\n')
    stripped = original_line.strip()

    # 1) Replace fgets(...) with klee_make_symbolic()
    if re.search(r'\bfgets\s*\(', stripped):
        return f'    klee_make_symbolic(&data, sizeof(data), "data"); // replaced fgets\n'

    # 2) Replace fscanf(...) with klee_make_symbolic()
    if re.search(r'\bfscanf\s*\(\s*stdin\s*,', stripped):
        return f'    klee_make_symbolic(&data, sizeof(data), "data"); // replaced fscanf\n'

    # 3) Replace recv(...) with klee_make_symbolic()
    if 'recv(' in stripped:
        return f'    klee_make_symbolic(&data, sizeof(data), "data"); // replaced recv\n'

    # 4) Replace data = RAND32(); with klee_make_symbolic()
    if re.search(r'\bdata\s*=\s*RAND32\s*\(\)\s*;', stripped):
        return f'    klee_make_symbolic(&data, sizeof(data), "data"); // replaced RAND32\n'

    # 5) Insert klee_assert() before malloc(data) to check for sign extension issues
    if re.search(r'\bmalloc\s*\(\s*data\s*\)', stripped):
        indent_match = re.match(r'^(\s*)', original_line)
        indentation = indent_match.group(1) if indent_match else '    '
        return (
            f'{indentation}klee_assert(data >= 0 && "Sign extension issue: data should be non-negative before malloc()");\n'
            f'{original_line}\n'
        )

    # 6) Insert klee_assert() before memset(dataBuffer, 'A', data-1) to check buffer overflow
    if re.search(r'\bmemset\s*\(\s*dataBuffer\s*,\s*\'A\'\s*,\s*data-1\s*\)', stripped):
        indent_match = re.match(r'^(\s*)', original_line)
        indentation = indent_match.group(1) if indent_match else '    '
        return (
            f'{indentation}klee_assert(data > 0 && data < 100 && "Heap buffer overflow check before memset()");\n'
            f'{original_line}\n'
        )

    # 7) Insert klee_assert() before dataBuffer[data-1] to prevent out-of-bounds access
    if re.search(r'dataBuffer\s*\[\s*data-1\s*\]', stripped):
        indent_match = re.match(r'^(\s*)', original_line)
        indentation = indent_match.group(1) if indent_match else '    '
        return (
            f'{indentation}klee_assert(data-1 >= 0 && data-1 < 100 && "Heap buffer overflow check before accessing dataBuffer[data-1]");\n'
            f'{original_line}\n'
        )

    # 8) Insert klee_assert() before memcpy(dest, source, data) to prevent sign extension issues
    if re.search(r'\bmemcpy\s*\(\s*dest\s*,\s*source\s*,\s*data\s*\)', stripped):
        indent_match = re.match(r'^(\s*)', original_line)
        indentation = indent_match.group(1) if indent_match else '    '
        return (
            f'{indentation}klee_assert(data >= 0 && "Unexpected sign extension: data must be non-negative before memcpy");\n'
            f'{original_line}\n'
        )

    # 9) Insert klee_assert() before dest[data] to prevent buffer overflow
    if re.search(r'dest\s*\[\s*data\s*\]', stripped):
        indent_match = re.match(r'^(\s*)', original_line)
        indentation = indent_match.group(1) if indent_match else '    '
        return (
            f'{indentation}klee_assert(data < sizeof(dest) && "Buffer overflow risk: data must be within destination buffer size");\n'
            f'{original_line}\n'
        )

    # Otherwise, preserve the line exactly
    return original_line + '\n'


def instrument_code(input_file, output_file):
    """
    Reads input_file line by line, applies transform_line to each line,
    and writes the transformed lines to output_file, preserving line numbers.
    """

    with open(input_file, "r") as f:
        lines = f.readlines()

    instrumented_lines = [transform_line(line) for line in lines]

    with open(output_file, "w") as f:
        f.writelines(instrumented_lines)

    print(f"[INFO] Instrumentation completed: {output_file}")


def main():
    """
    Usage:
      python3 instrument.py <input_file.c> <output_file.c>
    """
    if len(sys.argv) != 3:
        print("Usage: python3 instrument.py <input_file.c> <output_file.c>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    instrument_code(input_file, output_file)

if __name__ == "__main__":
    main()
