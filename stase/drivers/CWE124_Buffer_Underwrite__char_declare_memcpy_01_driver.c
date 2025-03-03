#include <stdio.h>
#include "klee/klee.h"
#include "../instrumented_code/CWE124_Buffer_Underwrite__char_declare_memcpy_01.c"

int main() {
    CWE124_Buffer_Underwrite__char_declare_memcpy_01_bad();
    CWE124_Buffer_Underwrite__char_declare_memcpy_01_good();
    return 0;
}
