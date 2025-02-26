#include <stdio.h>
#include "klee/klee.h"
#include "../instrumented_code/CWE122_Heap_Based_Buffer_Overflow__CWE131_memcpy_01.c"

int main() {
    CWE122_Heap_Based_Buffer_Overflow__CWE131_memcpy_01_bad();
    CWE122_Heap_Based_Buffer_Overflow__CWE131_memcpy_01_good();
    return 0;
}
