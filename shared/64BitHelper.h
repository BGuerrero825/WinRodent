#pragma once
#include <Windows.h>
#if defined(_WIN64)
extern void AlignRSP( void );

void Begin( void )
{
    // Call the ASM stub that will guarantee 16-byte stack alignment.
    // The stub will then call the ExecutePayload.
    AlignRSP();
}
#endif