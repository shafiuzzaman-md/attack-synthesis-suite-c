#!/usr/bin/env python3

import re
import sys

def transform_line(line):
    """
    Replaces certain patterns inline, ensuring we don't change the line count:
      1) If the line has 'fgets(...)', transform it to a single line with 'klee_make_symbolic(...)'
      2) If the line has 'recv(' => 'klee_make_symbolic(...)'
      3) If the line has 'buffer[data] =', transform it to a 'klee_assert(...)' line
      4) If the line has 'printLine(' or 'printIntLine(', comment it out

    Returns exactly one line (with a newline) so that line numbering is preserved.
    """

    # We'll keep the original indentation
    # so that code structure remains somewhat intact,
    # but transform the relevant statement in place.
    original_line = line.rstrip('\n')  # remove trailing newline only
    stripped = original_line.strip()

    # 1) Regex to match 'fgets(..., ..., stdin)'
    if re.search(r'\bfgets\s*\(', stripped):
        return f'    klee_make_symbolic(&data, sizeof(data), "data"); // replaced inline: {stripped}\n'

    # 2) If line mentions 'recv('
    if 'recv(' in stripped:
        return f'    klee_make_symbolic(&data, sizeof(data), "data"); // replaced inline: {stripped}\n'

    # 3) If line mentions 'buffer[data] ='
    if 'buffer[data] =' in stripped:
        return f'    klee_assert(data >= 0 && data < (int)(sizeof(buffer) / sizeof(buffer[0])) && "Stack based buffer overflow check"); // replaced inline: {stripped}\n'

    # 4) If line has 'printLine(' or 'printIntLine(', comment it out
    if 'printLine(' in stripped or 'printIntLine(' in stripped:
        # Keep indentation but comment out the entire line
        # We'll capture leading spaces and re-insert them for minimal disruption
        indent_match = re.match(r'^(\s*)', original_line)
        indentation = indent_match.group(1) if indent_match else ''
        return f'{indentation}// {stripped}\n'

    # Otherwise, preserve the line exactly
    return original_line + '\n'

def instrument_code(input_file, output_file):
    with open(input_file, "r") as f:
        lines = f.readlines()

    instrumented_lines = []
    for line in lines:
        new_line = transform_line(line)
        instrumented_lines.append(new_line)

    with open(output_file, "w") as f:
        f.writelines(instrumented_lines)

    print(f"[INFO] Instrumentation completed: {output_file}")

def main():
    """
    Usage:
      python instrument.py <input_file.c> <output_file.c>
    """
    if len(sys.argv) != 3:
        print("Usage: python instrument.py <input_file.c> <output_file.c>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    instrument_code(input_file, output_file) 

if __name__ == "__main__":
    main()
