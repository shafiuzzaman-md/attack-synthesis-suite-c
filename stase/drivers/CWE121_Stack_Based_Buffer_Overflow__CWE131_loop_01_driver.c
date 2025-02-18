#include <stdio.h>
#include "klee/klee.h"
#include "../instrumented_code/CWE121_Stack_Based_Buffer_Overflow__CWE131_loop_01.c"

int main() {
    CWE121_Stack_Based_Buffer_Overflow__CWE131_loop_01_bad();
    CWE121_Stack_Based_Buffer_Overflow__CWE131_loop_01_good();
    return 0;
}
