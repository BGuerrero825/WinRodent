Created by: Brian Guerrero
v1.0, 15 July 2024

# Documentation

This project implements many features that would be present and helpful in an Implant + Command and Control Server product. The implant is built in two forms a DLL version and a PIC (Position Independent Code) version. The DLL Implant still requires a PIC Implant for some of its features (such as process migration) but can be helpful for debugging as it can be ran / attached to with source.

### Running the Project
First, build the project to produce necessary binaries to the 'out' directory (assuming use of provided .sln file in Visual Studio). If running the files post-build with the default file output locations, set the 'out' directory as the working directory and run all script and binaries relative to that location.

Ex. with CNCServer.py and TestPayload.cpp
Server: `../CNCServer/CNCServer.py 127.0.0.1`
Client: `TestPayload.exe /DLL ImplantDLL.dll ImplantPIC_shellcode.bin`

OR

Ex. with VulnService.exe, MockExploit.py and CNCServer.py
Server: `../CNCServer/CNCServer.py 127.0.0.1`
Client: `VulnService.exe`
Exploit: `..\MockExploit\MockExploit.py 127.0.0.1 127.0.0.1 31337 .\ImplantPIC_shellcode.bin`

First, a server must be started with the CNCServer.py script. Then, a client must be started with TestPayload.cpp to simulate injection of the Implant on the client system, passing in the payload option to use and a path to the needed payloads(s). Alternatively, a client vulnerable service can be started with VulnService.exe and a exploit serving the implant can be thrown at it with MockExploit.py. 
Once the client is ran, the server will receive a connection from the injected implant and prompt the user for tasking to send to the implant.

 
## Server Commands / Implant Capabilities
---
The only way to interact with the implant is send it commands over the network with the provided server. The server has access to the commands listed below. 

Help:
Prints brief usage information about each of the following commands. Useful for determing how to format a specific command.

PutFile:
Takes two strings as a file name and file contents to write to the client's filesystem. The location of the file is the default location specified by the context of the current file. However, an absolute or relative path can be specified as per the Windows `CreateFileA` function. The file will always be overwritten in the case the file already exists.

GetFile:
Takes one string as the file name to be retrieved, printing the files contents to the server's output stream. The same rules apply in regards to file location as do with PutFile.

Survey:
Retrieves various OS and process information from the client system / current process, stored via the process heap, and returned to the server over the socket.
1. The version, build, and service pack (if provided) of the client's OS.
    - Virtualization, if detected, will also be shown with the retrieved Hypervisor signature from the CPUID instruction.
2. A list of running process names / executables and process IDs from the client system.
3. The current process executable path and PID along with the access privileges the current process possesses.

AddModule:
Takes one string as a command module name. Retrieves the specified command binary file from the server filesystem and sends it to the client implant. The implant then allocates memory in the current process to store this binary as code and saves a reference to it for later execution. This command is useful for adding the 'Persist', 'Migrate', and 'Test' commands to the implant as they are not included in the base implant code. 

Persist: (Requires 'AddModule')
Takes a string 'on' or 'off' as a mode specifier. With 'on': retrieves an implant startup executable from the server filesystem and sends it to the client implant. The implant then writes a value to HKCU:Run key to start an executable on system startup. If this succeeds, the executable is copied to the corresponding file path on disk and a separate data file is written alongside it containing the implant code and relevant config information. Loaded modules are not copied (to reduce footprint on the client). When ran, the executable copies the contents of the data file into itself then run the implant code, calling back to the server. With 'off': deletes the created registry key value, executable file, and data file.

Migrate: (Requires 'AddModule')
Takes a PID as a target process to migrate into (use 'Survey'). The implant then allocates memory within the specified process and injects it with the implant code, config structure, and already loaded modules. If this succeeds, a new thread is spawned in the target process to execute the injected implant code and the current implant proceeds to cleanup. The server will then receive a callback from the new process and can continue tasking. 

Test: (Requires 'AddModule')
Simply creates a string in client process memory, prints it via DebugPrint on the client, and returns it to the server to confirm execution. This command module is useful to test proper functionality of the 'AddModule' command.

EndTasking:
Signals the implant to proceed to cleanup and closes communication with the current client. The server will stay active and wait for further connections.

Exit:
Performs the same functionality as 'EndTasking' but also shuts down the Python server. Using Ctrl-C at the terminal performs 'Exit'.

## Message Encryption
--- 
To avoid communcation over plaintext, the server and implement a simple encryption methodology. 
1. 4 prime numbers are statically set in the implant and server code (they should match but are not sent over the network).
2. On startup, the implant generates a pseudo random number based on the system time at execution and sends this to the server.
3. Both server and implant independently perform modulus on the generated number using the 4 prime numbers to create shift keys 1 through 4.
    - Ex. Random number = 25; Primes = [3, 5, 7, 11]; Then, Shift Keys = [1, 0, 4, 3]
4. When sending a message, the first byte value is shifted right (increases value) by shift key 1, then the second by shift key 2, etc. repeating shift keys until the end of the data.
5. When receiving a message, the same logic is followed but instead shifting left (decreasing value) per shift key. 

## Solution Structure
---
There are 8 projects in the solution that are needed for proper execution of the product. 
1. CNCServer
2. TestPayload
Implants
3. ImplantDLL
4. ImplantPIC
Modules
5. Migrate
6. Persist
7. Test
Persistence Executable
8. StartupExe

Modules that are built into the implants ('PutFile', 'AddModule', etc.) are stored in their own .c files, but are included into the ImplantDLL and ImplantPIC projects so they are statically linked at compile time. 
Modules that must be added to the implant are built in their own projects so that they produce their own executables and can be prepended with helpers (AdjustStack.asm) to aid program entry through PIC. In a post build event, the the code section of these executables are stripped out and placed as .bin files alongside the CNCServer (so they can be sent to the client at server runtime). StartupExe, the persistence executable is also built as a separate project to produce an executable that is placed alongside the CNCServer.

Resources shared among the two Implants are saved in the shared folder and included as needed among the projects. Config.h contains most shared definitions and structures which are used across ImplantPIC, ImplantDLL and the individual modules. 