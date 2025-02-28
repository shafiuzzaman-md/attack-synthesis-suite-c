#include <stdio.h>
#include "klee/klee.h"
#include "../instrumented_code/CWE190_Integer_Overflow__char_fscanf_multiply_01.c"

int main() {
    CWE190_Integer_Overflow__char_fscanf_multiply_01_bad();
    CWE190_Integer_Overflow__char_fscanf_multiply_01_good();
    return 0;
}
