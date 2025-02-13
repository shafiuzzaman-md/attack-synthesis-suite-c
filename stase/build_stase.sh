#!/bin/bash

# Stop the execution if any command fails
set -e


# Use the full path to the KLEE executable
KLEE="/home/shafi/klee_build/bin/klee"

# Define an array of source files
sources=("stase_main.c")

# Define an array of output file names corresponding to the source files
outputd=("CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_01_bad.txt")

# Ensure that both arrays have the same length
if [ ${#sources[@]} -ne ${#outputd[@]} ]; then
    echo "Error: sources and outputd arrays have different lengths."
    exit 1
fi

# Loop over each source file using indices
for i in "${!sources[@]}"; do
    src="${sources[$i]}"
    output_file_name="${outputd[$i]}"
    echo "Processing $src"

    # Define filenames
    base_name="${src%.c}"
    bc_file="${base_name}.bc"
    klee_output_file="${base_name}_output.txt"

    # Step 1: Compile the C file into LLVM bitcode
    clang-14 -emit-llvm -c -g -O0 -Xclang -disable-O0-optnone "./${src}" -o "${bc_file}"
    echo "Compiled ${src} to ${bc_file}"

    # Step 2: Run KLEE on the LLVM bitcode
    "$KLEE" --external-calls=all -libc=uclibc --posix-runtime --smtlib-human-readable \
        --write-test-info --write-paths --write-smt2s --write-cov --write-cvcs \
        --write-kqueries --write-sym-paths --only-output-states-covering-new \
        --use-query-log=solver:smt2 --simplify-sym-indices --max-time=5 "$bc_file" > "$klee_output_file" 2>&1
    echo "Ran KLEE on ${bc_file}, output redirected to ${klee_output_file}"

    # Step 3: Run the Python script to extract the signature
    # Pass both the source file path and the desired output file name
    python3 extract_signature.py "${src}" "${output_file_name}"
    echo "Extracted signature for ${src} and saved to ${output_file_name}"

    echo "Finished processing $src"
    echo "----------------------------------------"
done

echo "All source files have been processed."
