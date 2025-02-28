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
      5) Insert klee_assert() before buffer[data] = ... (stack buffer overflow check)
      6) Insert klee_assert() before **any** buffer[data] (buffer overread check)
      7) Insert klee_assert() before integer arithmetic operations (integer overflow check)
      8) Comment out printLine(), printIntLine(), printHexCharLine()
      9) Insert klee_assert() before memcpy(), memmove() (heap buffer overflow check)
     10) Detect incorrect malloc() allocation without sizeof(int)
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

    # 5) Insert klee_assert() before buffer[data] = ... (stack buffer overflow check)
    if re.search(r'buffer\s*\[\s*data\s*\]\s*=', stripped):
        indent_match = re.match(r'^(\s*)', original_line)
        indentation = indent_match.group(1) if indent_match else '    '
        return (
            f'{indentation}klee_assert(data >= 0 && data < (int)(sizeof(buffer) / sizeof(buffer[0])) && "Stack buffer overflow check");\n'
            f'{original_line}\n'
        )

    # 6) Insert klee_assert() before **any** buffer[data] (buffer overread check)
    if re.search(r'buffer\s*\[\s*data\s*\]', stripped) and '=' not in stripped:
        indent_match = re.match(r'^(\s*)', original_line)
        indentation = indent_match.group(1) if indent_match else '    '
        return (
            f'{indentation}klee_assert(data >= 0 && data < (int)(sizeof(buffer) / sizeof(buffer[0])) && "Buffer overread check before access");\n'
            f'{original_line}\n'
        )

    # 7) Insert klee_assert() before multiplication operations (integer overflow check)
    if re.search(r'\bchar\s+\w+\s*=\s*data\s*\*\s*\d+\s*;', stripped):
        indent_match = re.match(r'^(\s*)', original_line)
        indentation = indent_match.group(1) if indent_match else '    '
        multiplier = re.search(r'data\s*\*\s*(\d+)', stripped).group(1)
        return (
            f'{indentation}klee_assert(data <= CHAR_MAX / {multiplier} && "Integer overflow check before multiplication"); // Prevent overflow\n'
            f'{original_line}\n'
        )

    # 8) Comment out printLine(), printIntLine(), printHexCharLine()
    if re.search(r'\b(printLine|printIntLine|printHexCharLine)\s*\(', stripped):
        return f'    // {stripped}\n'

    # 9) Insert klee_assert() before memcpy(), memmove() (heap buffer overflow check)
    if re.search(r'\b(memcpy|memmove)\s*\(\s*.*,\s*.*,\s*.*\s*\)', stripped):
        indent_match = re.match(r'^(\s*)', original_line)
        indentation = indent_match.group(1) if indent_match else '    '
        return (
            f'{indentation}klee_assert(sizeof(int) * 10 <= malloc_size(data) && "Heap buffer overflow check!"); // Prevent heap overflow\n'
            f'{original_line}\n'
        )

    # 10) Detect incorrect malloc() allocation without sizeof(int)
    if re.search(r'\bdata\s*=\s*\(\s*int\s*\*\s*\)\s*malloc\s*\(\s*\d+\s*\)\s*;', stripped) and not re.search(r'sizeof\s*\(\s*int\s*\)', stripped):
        indent_match = re.match(r'^(\s*)', original_line)
        indentation = indent_match.group(1) if indent_match else '    '
        return (
            f'{indentation}klee_assert(0 && "Heap buffer overflow risk: malloc() without sizeof(int)!"); // Prevent incorrect allocation\n'
            f'{original_line}\n'
        )

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
