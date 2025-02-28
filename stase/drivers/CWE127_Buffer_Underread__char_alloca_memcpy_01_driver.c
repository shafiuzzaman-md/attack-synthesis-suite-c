#include <stdio.h>
#include "klee/klee.h"
#include "../instrumented_code/CWE127_Buffer_Underread__char_alloca_memcpy_01.c"

int main() {
    CWE127_Buffer_Underread__char_alloca_memcpy_01_bad();
    CWE127_Buffer_Underread__char_alloca_memcpy_01_good();
    return 0;
}
