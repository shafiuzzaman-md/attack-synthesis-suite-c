#include <stdio.h>
#include "klee/klee.h"
#include "../instrumented_code/CWE127_Buffer_Underread__CWE839_fscanf_01.c"

int main() {
    CWE127_Buffer_Underread__CWE839_fscanf_01_bad();
    CWE127_Buffer_Underread__CWE839_fscanf_01_good();
    return 0;
}
