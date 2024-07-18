/*
PIC module to be sent as stripped binary code to the implant, then added to its modules struct.
Used for testing proper transmission, allocation, and execution of modules added to the implant.
*/

#define WIN32_LEAN_AND_MEAN

#pragma warning( disable : 4201 ) // Disable warning about 'nameless struct/union'

#include "../shared/64BitHelper.h"
#include "../shared/Config.h"

// Given generic name "ModuleEntry" for reuse of Post-Build CLI command which extract the PIC binary
/*
* @brief Creates a test string and returns it to the supplied Data buffer
* @param [in] Config network context, dynamic imports, and runtime data
* @param [in] Message Pointer to message containing Test command data
* @param [out], Address of unsigned to output number of data bytes read
* @param [out], Address of uint8_t pointer to output resulting data buffer (must be freed with HeapFree after use)
* @return true on success / false on failure
*/
bool ModuleEntry(PCONFIG Config, unsigned * DataLen, uint8_t ** Data)
{
	uint8_t outstr[] = {'T', 'e', 's', 't', ' ', 'r', 'a', 'n', '!', '\n', '\0'};
	if (!(NT_SUCCESS(Config->Imports->DbgPrint((const char *) outstr))))
	{
		return false;
	}
	unsigned dataLen = sizeof(outstr);
	uint8_t * data = Config->Imports->HeapAlloc(Config->Imports->GetProcessHeap(), 0, dataLen);
	if (!data)
	{
		return false;
	}
	Config->Imports->memcpy_s(data, dataLen, outstr, dataLen);

	*DataLen = dataLen;
	*Data = data;

	return true;
}
