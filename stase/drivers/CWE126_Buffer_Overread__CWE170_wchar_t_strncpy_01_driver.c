#include <stdio.h>
#include "klee/klee.h"
#include "../instrumented_code/CWE126_Buffer_Overread__CWE170_wchar_t_strncpy_01.c"

int main() {
    CWE126_Buffer_Overread__CWE170_wchar_t_strncpy_01_bad();
    CWE126_Buffer_Overread__CWE170_wchar_t_strncpy_01_good();
    return 0;
}
