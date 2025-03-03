#include <stdio.h>
#include "klee/klee.h"
#include "../instrumented_code/CWE194_Unexpected_Sign_Extension__negative_memcpy_01.c"

int main() {
    CWE194_Unexpected_Sign_Extension__negative_memcpy_01_bad();
    CWE194_Unexpected_Sign_Extension__negative_memcpy_01_good();
    return 0;
}
