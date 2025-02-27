#!/bin/bash
#
# This script processes multiple Juliet test files:
#   1) Instruments each source file (placing output in instrumented_code/)
#   2) Generates a driver in drivers/ folder calling all _bad() and _good() functions.
#   3) Compiles the driver to LLVM bitcode inside klee_output/.
#   4) Runs KLEE on the bitcode inside klee_output/.
#   5) Calls extract_signature.py to generate the vulnerability signature.
#

set -e  # Exit on error

#######################################################
# Path to KLEE executable
#######################################################
KLEE="/home/shafi/klee_build/bin/klee"

#######################################################
# Define an array of source files to process
#######################################################
SOURCES=(
  #"../testcases/CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_01.c"
  #"../testcases/CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_01.c"
 # "../testcases/CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_Stack_Based_Buffer_Overflow__CWE129_fscanf_01.c"
 # "../testcases/CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_Stack_Based_Buffer_Overflow__CWE129_large_01.c"
 # "../testcases/CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_Stack_Based_Buffer_Overflow__CWE129_listen_socket_01.c"
  #"../testcases/CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_Stack_Based_Buffer_Overflow__CWE129_rand_01.c"
    #"../testcases/CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_Stack_Based_Buffer_Overflow__CWE131_loop_01.c"
    #  "../testcases/CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_01.c"
    #    "../testcases/CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_01.c"
     #     "../testcases/CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_Stack_Based_Buffer_Overflow__CWE135_01.c"
     #"../testcases/CWE122_Heap_Based_Buffer_Overflow/s01/CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_01.c"
    # "../testcases/CWE122_Heap_Based_Buffer_Overflow/s01/CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memmove_01.c"
    #"../testcases/CWE122_Heap_Based_Buffer_Overflow/s05/CWE122_Heap_Based_Buffer_Overflow__CWE131_loop_01.c"
    #"../testcases/CWE122_Heap_Based_Buffer_Overflow/s05/CWE122_Heap_Based_Buffer_Overflow__CWE131_memcpy_01.c"
    #"../testcases/CWE126_Buffer_Overread/s01/CWE126_Buffer_Overread__CWE129_fgets_01.c"
    #"../testcases/CWE126_Buffer_Overread/s01/CWE126_Buffer_Overread__CWE129_fscanf_01.c"
    #"../testcases/CWE126_Buffer_Overread/s01/CWE126_Buffer_Overread__CWE129_large_01.c"
    #"../testcases/CWE126_Buffer_Overread/s02/CWE126_Buffer_Overread__CWE170_wchar_t_strncpy_01.c"
    #"../testcases/CWE126_Buffer_Overread/s02/CWE126_Buffer_Overread__malloc_char_loop_01.c"
   # "../testcases/CWE126_Buffer_Overread/s02/CWE126_Buffer_Overread__malloc_char_loop_01.c"
   #"../testcases/CWE126_Buffer_Overread/s02/CWE126_Buffer_Overread__malloc_char_memcpy_01.c"
   # "../testcases/CWE126_Buffer_Overread/s02/CWE126_Buffer_Overread__malloc_char_memmove_01.c"
   # "../testcases/CWE126_Buffer_Overread/s02/CWE126_Buffer_Overread__malloc_wchar_t_loop_01.c"
   # "../testcases/CWE126_Buffer_Overread/s02/CWE126_Buffer_Overread__malloc_wchar_t_memcpy_01.c"
   # "../testcases/CWE126_Buffer_Overread/s02/CWE126_Buffer_Overread__malloc_wchar_t_memmove_01.c"
)

#######################################################
# Output directories
#######################################################
INSTRUMENTED_DIR="instrumented_code"
DRIVERS_DIR="drivers"
KLEE_OUTPUT_DIR="klee_output"
SIGNATURE_DIR="stase_output"

mkdir -p "$INSTRUMENTED_DIR" "$DRIVERS_DIR" "$KLEE_OUTPUT_DIR"

#######################################################
# Process each source file
#######################################################
for ORIGINAL_SRC in "${SOURCES[@]}"; do
    BASE_FILE="$(basename "$ORIGINAL_SRC")"
    BASE_NAME="${BASE_FILE%.c}"

    INSTRUMENTED_SRC="${INSTRUMENTED_DIR}/${BASE_NAME}.c"
    DRIVER_FILE="${DRIVERS_DIR}/${BASE_NAME}_driver.c"
    BC_FILE="${KLEE_OUTPUT_DIR}/${BASE_NAME}_driver.bc"
    KLEE_OUTPUT_FILE="${KLEE_OUTPUT_DIR}/${BASE_NAME}_klee_output.txt"
    SIGNATURE_FILE="${SIGNATURE_DIR}/${BASE_NAME}.txt"

    echo "========================================"
    echo "[INFO] Processing source: $ORIGINAL_SRC"
    echo "      Instrumented file: $INSTRUMENTED_SRC"
    echo "      Driver file:       $DRIVER_FILE"
    echo "      Bitcode file:      $BC_FILE"
    echo "      KLEE output:       $KLEE_OUTPUT_FILE"
    echo "      Signature output:  $SIGNATURE_FILE"
    echo "========================================"

    #######################################################
    # Step 1: Instrument the source file
    #######################################################
    echo "[STEP] Instrumenting code"
    python3 instrument.py "$ORIGINAL_SRC" "$INSTRUMENTED_SRC"
    echo "[DONE] Instrumentation"

    #######################################################
    # Step 2: Extract _bad() and _good() function names
    #######################################################
    FUN_BAD=()
    FUN_GOOD=()

    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*void[[:space:]]+([A-Za-z0-9_]+)_bad[[:space:]]*\( ]]; then
            FUN_BAD+=( "${BASH_REMATCH[1]}_bad" )
        elif [[ "$line" =~ ^[[:space:]]*void[[:space:]]+([A-Za-z0-9_]+)_good[[:space:]]*\( ]]; then
            FUN_GOOD+=( "${BASH_REMATCH[1]}_good" )
        fi
    done < "$INSTRUMENTED_SRC"

    echo "[INFO] Found _bad functions: ${FUN_BAD[@]}"
    echo "[INFO] Found _good functions: ${FUN_GOOD[@]}"

    #######################################################
    # Step 3: Generate Driver File
    #######################################################
    REL_INSTRUMENTED="../${INSTRUMENTED_SRC}"

    echo "[STEP] Generating driver: $DRIVER_FILE"
    cat <<EOF > "$DRIVER_FILE"
#include <stdio.h>
#include "klee/klee.h"
#include "../${INSTRUMENTED_SRC}"

int main() {
EOF

    for fn in "${FUN_BAD[@]}"; do
cat <<EOF >> "$DRIVER_FILE"
    ${fn}();
EOF
    done

    for fn in "${FUN_GOOD[@]}"; do
cat <<EOF >> "$DRIVER_FILE"
    ${fn}();
EOF
    done

    cat <<EOF >> "$DRIVER_FILE"
    return 0;
}
EOF

    echo "[DONE] Driver generated: $DRIVER_FILE"

    #######################################################
    # Step 4: Compile Driver to LLVM Bitcode in klee_output/
    #######################################################
    echo "[STEP] Compiling driver to bitcode: $BC_FILE"
    clang-14 -emit-llvm -c -g -O0 -Xclang -disable-O0-optnone "$DRIVER_FILE" -o "$BC_FILE"
    echo "[DONE] Compilation completed: $BC_FILE"

    #######################################################
    # Step 5: Run KLEE inside klee_output/
    #######################################################
    echo "[STEP] Running KLEE on $BC_FILE"
    (cd "$KLEE_OUTPUT_DIR" && "$KLEE" --external-calls=all -libc=uclibc --posix-runtime --smtlib-human-readable \
        --write-test-info --write-paths --write-smt2s --write-cov --write-cvcs \
        --write-kqueries --write-sym-paths --only-output-states-covering-new \
        --use-query-log=solver:smt2 --simplify-sym-indices --max-time=5 \
        "$(basename "$BC_FILE")" > "$(basename "$KLEE_OUTPUT_FILE")" 2>&1)
    echo "[DONE] KLEE run completed, output in $KLEE_OUTPUT_FILE"

    #######################################################
    # Step 6: Extract Signature from KLEE output
    #######################################################
    echo "[STEP] Extracting signature using KLEE output from $KLEE_OUTPUT_FILE to $SIGNATURE_FILE"
    python3 extract_signature.py "$KLEE_OUTPUT_FILE" "$SIGNATURE_FILE"
    echo "[DONE] Signature extracted to $SIGNATURE_FILE"

    #######################################################
    # Step 7: Call generate_effects.py with signature files
    #######################################################
    echo "[INFO] Generating effect functions..."
    EFFECT_SCRIPT_PATH="$(realpath ../effectfunctions/scripts/generate_effects.py)"
    python3 "$EFFECT_SCRIPT_PATH" "$SIGNATURE_FILE"
    echo "[DONE] ${SIGNATURE_FILES[@]} Effect functions generated."
    echo "[INFO] Finished processing $ORIGINAL_SRC"
    echo "----------------------------------------"
done

echo "[INFO] All processing completed."
