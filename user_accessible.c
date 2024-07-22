#include "common.h"

// Include the Juliet test suite file
#define OMITGOOD
#include "testcases/CWE121_Stack_Based_Buffer_Overflow__bad_wrappers.c"
#include "testcases/CWE457_Use_of_Uninitialized_Variable/s01/CWE457_Use_of_Uninitialized_Variable__char_pointer_01.c"

void CWE121_Stack_Based_Buffer_Overflow__CWE129_large_01_bad(int data);
void CWE121_Stack_Based_Buffer_Overflow__CWE129_large_02_bad(int data);
void CWE121_Stack_Based_Buffer_Overflow__CWE129_large_03_bad(int data);


// Uninitialized Variable Component
char* component_input_CWE78_bad(char *user_data) {
    CWE457_Use_of_Uninitialized_Variable__char_pointer_01_bad(user_data);
    return user_data;
}