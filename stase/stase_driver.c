#include "ECH.c"
#include "../testcases/CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_Stack_Based_Buffer_Overflow__CWE129_large_01.c"
int main()
{
   int user_data;
   user_data = klee_int("user_data");
   u_CWE121_CWE129_large_01_bad(user_data);
}