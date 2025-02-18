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
      4) If line has 'buffer[data] =', => replace with 'klee_assert(...)' line
      5) If line has 'printLine(' or 'printIntLine(', => comment it out
      6) If line has 'data = RAND32();', => replace with 'klee_make_symbolic(&data,...)'
      7) If line has 'data = (int *)ALLOCA(...)', => replace with 'klee_make_symbolic(&data,...)'

    Returns a single output line (with trailing newline).
    """

    # Original line minus the trailing newline
    original_line = line.rstrip('\n')
    stripped = original_line.strip()

    # 1) Regex to match 'fgets(..., ..., stdin)'
    if re.search(r'\bfgets\s*\(', stripped):
        return f'    klee_make_symbolic(&data, sizeof(data), "data"); // replaced inline: {stripped}\n'

    # 2) Check if line mentions 'recv('
    if 'recv(' in stripped:
        return f'    klee_make_symbolic(&data, sizeof(data), "data"); // replaced inline: {stripped}\n'

    # 3) Check for fscanf(stdin, "%d", &data)
    if 'fscanf(' in stripped and 'stdin' in stripped:
        return f'    klee_make_symbolic(&data, sizeof(data), "data"); // replaced inline: {stripped}\n'

    # 4) If line mentions 'buffer[data] ='
    if 'buffer[data] =' in stripped:
        return (
            '    klee_assert('
            'data >= 0 && '
            'data < (int)(sizeof(buffer) / sizeof(buffer[0])) && '
            '"Stack based buffer overflow check"); '
            f'// replaced inline: {stripped}\n'
        )

    # 5) If line has 'printLine(' or 'printIntLine(', comment it out
    if 'printLine(' in stripped or 'printIntLine(' in stripped:
        indent_match = re.match(r'^(\s*)', original_line)
        indentation = indent_match.group(1) if indent_match else ''
        return f'{indentation}// {stripped}\n'

    # 6) If line has 'data = RAND32();', => symbolic
    if re.search(r'\bdata\s*=\s*RAND32\s*\(\)\s*;', stripped):
        return f'    klee_make_symbolic(&data, sizeof(data), "data"); // replaced inline: {stripped}\n'

    # 7) If line has 'data = (int *)ALLOCA(...)', => symbolic pointer
    #    For simplicity, check substring 'data = (int *)ALLOCA('
    if 'data = (int *)ALLOCA(' in stripped:
        return f'    klee_make_symbolic(&data, sizeof(data), "data"); // replaced inline: {stripped}\n'

    # Otherwise, preserve the line exactly
    return original_line + '\n'


def instrument_code(input_file, output_file):
    """
    Reads the input_file line by line, transforms each line with transform_line,
    and writes the instrumented lines to output_file (preserving line counts).
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
        print("Usage: python instrument.py <input_file.c> <output_file.c>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    instrument_code(input_file, output_file)


if __name__ == "__main__":
    main()
