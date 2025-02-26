#include <stdio.h>
#include "klee/klee.h"
#include "../instrumented_code/CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memmove_01.c"

int main() {
    CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memmove_01_bad();
    CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memmove_01_good();
    return 0;
}
