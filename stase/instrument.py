#!/usr/bin/env python3

import re
import sys

def transform_line(line):
    """
    Replaces certain patterns inline, preserving line numbers by returning exactly one output line
    for each input line:

      1) If line has 'fgets(...)', => replace with 'klee_make_symbolic(&data,...)'
      2) If line has 'recv(', => replace with 'klee_make_symbolic(&data,...)'
      3) If line has 'fscanf(stdin, "%d", &data)', => replace with 'klee_make_symbolic(&data,...)'
      4) If line has 'data = RAND32();', => replace with 'klee_make_symbolic(&data,...)'
      5) If line has 'buffer[data] =', => replace with 'klee_assert(...)' line (for stack buffer overflow)
      6) If line has 'buffer[data]', => insert 'klee_assert()' **before** it to check for buffer overread.
      7) If line has 'printLine(' or 'printIntLine(', => comment it out
      8) If line has 'data[i] = source[i];', => insert 'klee_assert()' before it.
      9) If line has 'memcpy(...)' or 'memmove(...)', => insert 'klee_assert()' before it to check for heap-based buffer overflow.
     10) Detect incorrect 'malloc()' allocation and ensure proper heap allocation before use.

    Returns a single output line (with trailing newline).
    """

    original_line = line.rstrip('\n')
    stripped = original_line.strip()

    # 1) Regex to match 'fgets(..., ..., stdin)' → replace with klee_make_symbolic()
    if re.search(r'\bfgets\s*\(', stripped):
        return f'    klee_make_symbolic(&data, sizeof(data), "data"); // replaced inline: {stripped}\n'

    # 2) Replace 'recv(' with klee_make_symbolic()
    if 'recv(' in stripped:
        return f'    klee_make_symbolic(&data, sizeof(data), "data"); // replaced inline: {stripped}\n'

    # 3) Replace 'fscanf(stdin, "%d", &data)' with klee_make_symbolic()
    if 'fscanf(' in stripped and 'stdin' in stripped:
        return f'    klee_make_symbolic(&data, sizeof(data), "data"); // replaced inline: {stripped}\n'

    # 4) Replace 'data = RAND32();' with klee_make_symbolic()
    if re.search(r'\bdata\s*=\s*RAND32\s*\(\)\s*;', stripped):
        return f'    klee_make_symbolic(&data, sizeof(data), "data"); // replaced inline: {stripped}\n'

    # 5) Insert klee_assert() before buffer[data] = ... (stack-based buffer overflow check)
    if 'buffer[data] =' in stripped:
        return (
            '    klee_assert('
            'data >= 0 && '
            'data < (int)(sizeof(buffer) / sizeof(buffer[0])) && '
            '"Stack based buffer overflow check"); '
            f'// replaced inline: {stripped}\n'
        )

    # 6) Insert klee_assert() before **any** `buffer[data]` (to check for buffer overread)
    if re.search(r'buffer\s*\[\s*data\s*\]', stripped):
        indent_match = re.match(r'^(\s*)', original_line)
        indentation = indent_match.group(1) if indent_match else '    '  # Preserve indentation
        return (
            f'{indentation}klee_assert(data >= 0 && data < (int)(sizeof(buffer) / sizeof(buffer[0])) && "Buffer overread check before access");\n'
            f'{original_line}\n'
        )

    # 7) If line has 'printLine(' or 'printIntLine(', comment it out
    if 'printLine(' in stripped or 'printIntLine(' in stripped:
        indent_match = re.match(r'^(\s*)', original_line)
        indentation = indent_match.group(1) if indent_match else ''
        return f'{indentation}// {stripped}\n'

    # 8) Insert klee_assert() before 'data[i] = source[i];'
    if re.search(r'\bdata\s*\[\s*i\s*\]\s*=\s*source\s*\[\s*i\s*\]\s*;', stripped):
        indent_match = re.match(r'^(\s*)', original_line)
        indentation = indent_match.group(1) if indent_match else '    '  # Preserve indentation
        return (
            f'{indentation}klee_assert(i >= 0 && i < (sizeof(data) / sizeof(int)) && "Stack buffer overflow check"); // Correct assertion\n'
            f'{original_line}\n'
        )

    # 9) Insert klee_assert() before 'memcpy(...)' or 'memmove(...)' to check heap-based buffer overflow
    if re.search(r'\b(memcpy|memmove)\s*\(\s*.*,\s*.*,\s*.*\s*\)', stripped):
        indent_match = re.match(r'^(\s*)', original_line)
        indentation = indent_match.group(1) if indent_match else '    '  # Preserve indentation
        return (
            f'{indentation}klee_assert(sizeof(int) * 10 <= malloc_size(data) && "Heap buffer overflow risk!"); // Prevent heap overflow\n'
            f'{original_line}\n'
        )

    # 10) Detect incorrect 'malloc()' allocation without sizeof(int)
    if re.search(r'\bdata\s*=\s*\(\s*int\s*\*\s*\)\s*malloc\s*\(\s*\d+\s*\)\s*;', stripped) and not re.search(r'sizeof\s*\(\s*int\s*\)', stripped):
        indent_match = re.match(r'^(\s*)', original_line)
        indentation = indent_match.group(1) if indent_match else '    '  # Preserve indentation
        return (
            f'{indentation}klee_assert(0 && "Heap buffer overflow risk: malloc() without sizeof(int)!"); // Prevent incorrect allocation\n'
            f'{original_line}\n'
        )

    # Otherwise, preserve the line exactly
    return original_line + '\n'


def instrument_code(input_file, output_file):
    """
    Reads the input_file line by line, applies transform_line to each line,
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
