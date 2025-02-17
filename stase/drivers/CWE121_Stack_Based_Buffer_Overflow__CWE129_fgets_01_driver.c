#include <stdio.h>
#include "klee/klee.h"
#include "../instrumented_code/CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_01.c"

int main() {
    CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_01_bad();
    CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_01_good();
    return 0;
}
