#include <stdio.h>
#include "klee/klee.h"
#include "../instrumented_code/CWE190_Integer_Overflow__char_fscanf_add_02.c"

int main() {
    CWE190_Integer_Overflow__char_fscanf_add_02_bad();
    CWE190_Integer_Overflow__char_fscanf_add_02_good();
    return 0;
}
