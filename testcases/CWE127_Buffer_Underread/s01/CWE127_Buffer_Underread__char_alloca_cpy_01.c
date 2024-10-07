/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE127_Buffer_Underread__char_alloca_cpy_01.c
Label Definition File: CWE127_Buffer_Underread.stack.label.xml
Template File: sources-sink-01.tmpl.c
*/
/*
 * @description
 * CWE: 127 Buffer Under-read
 * BadSource:  Set data pointer to before the allocated memory buffer
 * GoodSource: Set data pointer to the allocated memory buffer
 * Sink: cpy
 *    BadSink : Copy data to string using strcpy
 * Flow Variant: 01 Baseline
 *
 * */

#include "../../../testcasesupport/std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

// Function that simulates buffer underread using a supplied buffer and input size
char* CWE127_Buffer_Underread__char_alloca_cpy_01_bad(char *buffer_to_read, size_t size_to_read) {
    char *data;

    /* FLAW: Set data pointer to before the allocated memory buffer */
    data = buffer_to_read - 8;

    char *dest = (char*)malloc(100 * 2 * sizeof(char)); // Allocate memory dynamically
    if (dest == NULL) {
        printLine("ERROR: Memory allocation failed.");
        return NULL;
    }

    memset(dest, 'C', 100 * 2 - 1); /* fill with 'C's */
    dest[100 * 2 - 1] = '\0'; /* null terminate */

    /* POTENTIAL FLAW: Possibly copy from a memory location located before the source buffer */
    strcpy(dest, data);
    printLine(dest);
    
    return dest; // Return the dynamically allocated buffer
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    char * data;
    char * dataBuffer = (char *)ALLOCA(100*sizeof(char));
    memset(dataBuffer, 'A', 100-1);
    dataBuffer[100-1] = '\0';
    /* FIX: Set data pointer to the allocated memory buffer */
    data = dataBuffer;
    {
        char dest[100*2];
        memset(dest, 'C', 100*2-1); /* fill with 'C's */
        dest[100*2-1] = '\0'; /* null terminate */
        /* POTENTIAL FLAW: Possibly copy from a memory location located before the source buffer */
        strcpy(dest, data);
        printLine(dest);
    }
}

void CWE127_Buffer_Underread__char_alloca_cpy_01_good()
{
    goodG2B();
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
 * its own for testing or for building a binary to use in testing binary
 * analysis tools. It is not used when compiling all the testcases as one
 * application, which is how source code analysis tools are tested.
 */

#ifdef INCLUDEMAIN

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    CWE127_Buffer_Underread__char_alloca_cpy_01_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE127_Buffer_Underread__char_alloca_cpy_01_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
