/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE124_Buffer_Underwrite__CWE839_fscanf_01.c
Label Definition File: CWE124_Buffer_Underwrite__CWE839.label.xml
Template File: sources-sinks-01.tmpl.c
*/
/*
 * @description
 * CWE: 124 Buffer Underwrite
 * BadSource: fscanf Read data from the console using fscanf()
 * GoodSource: Non-negative but less than 10
 * Sinks:
 *    GoodSink: Ensure the array index is valid
 *    BadSink : Improperly check the array index by not checking the lower bound
 * Flow Variant: 01 Baseline
 *
 * */

#include "std_testcase.h"

#ifndef OMITBAD

void CWE124_Buffer_Underwrite__CWE839_fscanf_01_bad()
{
    int data;
    /* Initialize data */
    data = -1;
    /* POTENTIAL FLAW: Read data from the console using fscanf() */
    klee_make_symbolic(&data, sizeof(data), "data"); // replaced fscanf
    {
        int i;
        int buffer[10] = { 0 };
        /* POTENTIAL FLAW: Attempt to access a negative index of the array
        * This code does not check to see if the array index is negative */
        if (data < 10)
        {
            klee_assert(data >= 0 && data < (int)(sizeof(buffer) / sizeof(buffer[0])) && "Stack buffer overflow check");
            buffer[data] = 1;
            /* Print the array values */
            for(i = 0; i < 10; i++)
            {
    // printIntLine(buffer[i]);
            }
        }
        else
        {
    // printLine("ERROR: Array index is negative.");
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    int data;
    /* Initialize data */
    data = -1;
    /* FIX: Use a value greater than 0, but less than 10 to avoid attempting to
    * access an index of the array in the sink that is out-of-bounds */
    data = 7;
    {
        int i;
        int buffer[10] = { 0 };
        /* POTENTIAL FLAW: Attempt to access a negative index of the array
        * This code does not check to see if the array index is negative */
        if (data < 10)
        {
            klee_assert(data >= 0 && data < (int)(sizeof(buffer) / sizeof(buffer[0])) && "Stack buffer overflow check");
            buffer[data] = 1;
            /* Print the array values */
            for(i = 0; i < 10; i++)
            {
    // printIntLine(buffer[i]);
            }
        }
        else
        {
    // printLine("ERROR: Array index is negative.");
        }
    }
}

/* goodB2G uses the BadSource with the GoodSink */
static void goodB2G()
{
    int data;
    /* Initialize data */
    data = -1;
    /* POTENTIAL FLAW: Read data from the console using fscanf() */
    klee_make_symbolic(&data, sizeof(data), "data"); // replaced fscanf
    {
        int i;
        int buffer[10] = { 0 };
        /* FIX: Properly validate the array index and prevent a buffer underwrite */
        if (data >= 0 && data < (10))
        {
            klee_assert(data >= 0 && data < (int)(sizeof(buffer) / sizeof(buffer[0])) && "Stack buffer overflow check");
            buffer[data] = 1;
            /* Print the array values */
            for(i = 0; i < 10; i++)
            {
    // printIntLine(buffer[i]);
            }
        }
        else
        {
    // printLine("ERROR: Array index is out-of-bounds");
        }
    }
}

void CWE124_Buffer_Underwrite__CWE839_fscanf_01_good()
{
    goodG2B();
    goodB2G();
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */

#ifdef INCLUDEMAIN

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    // printLine("Calling good()...");
    CWE124_Buffer_Underwrite__CWE839_fscanf_01_good();
    // printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    // printLine("Calling bad()...");
    CWE124_Buffer_Underwrite__CWE839_fscanf_01_bad();
    // printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
