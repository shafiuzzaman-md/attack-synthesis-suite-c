#!/bin/bash
# Source .bashrc to ensure all path and other environmental variables are initialized
source ~/.bashrc

# Manually ensure KLEE's path is set in case sourcing .bashrc doesn't work
export PATH=$PATH:/usr/local/bin  # Change this to KLEE's actual path

# Define the Clang and LLVM tools version
CLANG="clang-14"
LLVM_LINK="llvm-link-14"
KLEE="klee"

# Source files
SRC_MAIN="stase_main.c"
SRC_PREDICATES="vulnerability_predicates.c"
SRC_ECH="ECH.c"

# Output bitcode files
BC_MAIN="stase_main.bc"
BC_PREDICATES="vulnerability_predicates.bc"
BC_ECH="ECH.bc"
BC_COMBINED="stase.bc"

# Compilation step for each source file
echo "Compiling source files to LLVM bitcode..."
$CLANG -emit-llvm -c -g -O0 -Xclang -disable-O0-optnone $SRC_MAIN -o $BC_MAIN
$CLANG -emit-llvm -c -g -O0 -Xclang -disable-O0-optnone $SRC_PREDICATES -o $BC_PREDICATES
$CLANG -emit-llvm -c -g -O0 -Xclang -disable-O0-optnone $SRC_ECH -o $BC_ECH

# Linking step to combine bitcode files
echo "Linking bitcode files..."
$LLVM_LINK $BC_MAIN $BC_PREDICATES $BC_ECH -o $BC_COMBINED

# Running KLEE on the combined bitcode
# echo "Running KLEE on the combined bitcode..."
# $KLEE --external-calls=all -libc=uclibc --posix-runtime --smtlib-human-readable  --write-test-info --write-paths --write-smt2s   --write-cov  --write-cvcs --write-kqueries   --write-sym-paths --only-output-states-covering-new --use-query-log=solver:smt2  --simplify-sym-indices $BC_COMBINED
