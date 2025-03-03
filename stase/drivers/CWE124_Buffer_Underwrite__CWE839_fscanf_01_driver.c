#include <stdio.h>
#include "klee/klee.h"
#include "../instrumented_code/CWE124_Buffer_Underwrite__CWE839_fscanf_01.c"

int main() {
    CWE124_Buffer_Underwrite__CWE839_fscanf_01_bad();
    CWE124_Buffer_Underwrite__CWE839_fscanf_01_good();
    return 0;
}
