#include <stdio.h>
#include "klee/klee.h"
#include "../instrumented_code/CWE126_Buffer_Overread__CWE129_fscanf_01.c"

int main() {
    CWE126_Buffer_Overread__CWE129_fscanf_01_bad();
    CWE126_Buffer_Overread__CWE129_fscanf_01_good();
    return 0;
}
