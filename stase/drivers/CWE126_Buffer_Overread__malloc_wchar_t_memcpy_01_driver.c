#include <stdio.h>
#include "klee/klee.h"
#include "../instrumented_code/CWE126_Buffer_Overread__malloc_wchar_t_memcpy_01.c"

int main() {
    CWE126_Buffer_Overread__malloc_wchar_t_memcpy_01_bad();
    CWE126_Buffer_Overread__malloc_wchar_t_memcpy_01_good();
    return 0;
}
