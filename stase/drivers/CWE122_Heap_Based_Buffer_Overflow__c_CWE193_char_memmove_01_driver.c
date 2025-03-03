#include <stdio.h>
#include "klee/klee.h"
#include "../instrumented_code/CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_memmove_01.c"

int main() {
    CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_memmove_01_bad();
    CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_memmove_01_good();
    return 0;
}
