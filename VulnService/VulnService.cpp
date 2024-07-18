// VulnService.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <iostream>
#include <winsock2.h>
#include <WS2tcpip.h>

#pragma comment(lib,"Ws2_32.lib")

#define PORT_NUM 12345

typedef enum MESSAGE_TYPE {
    OK = 0,
    ERR,
    CONFIG,
    PAYLOAD,
    EXEC,
    QUIT,
    MAX
} MESSAGE_TYPE;

#pragma pack(1)
struct MESSAGE_HEADER {
    MESSAGE_TYPE Type;
    uint32_t Length;
};

/**
 * @brief Dump payload to a file for debugging
 *
 * @param Payload Pointer to payload
 * @param Length Size of payload in bytes
*/
bool DumpPayload(void* Payload, unsigned Length)
{
    if (!Payload || !Length)
    {
        return false;
    }

    HANDLE hFile = CreateFileA("payload_debug.bin", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[!] Error: CreateFile('payload_debug.bin') failed: %d\n", GetLastError());
        return false;
    }

    bool rv = true;
    uint32_t nbytes;
    if (!WriteFile(hFile, Payload, Length, (DWORD*) & nbytes, NULL))
    {
        printf("[!] Error: WriteFile('payload_debug.bin', %u bytes) failed: %d\n", Length, GetLastError());
        rv = false;
    }
    else if (nbytes != Length)
    {
        printf("[!] Error: WriteFile('payload_debug.bin') wrote %u bytes, but expected %u\n", nbytes, Length);
        rv = false;
    }
    CloseHandle(hFile);
    return rv;
}

void SendOk(SOCKET ClientSocket)
{
    MESSAGE_HEADER OkHeader = { OK, 0 };
    send(ClientSocket, (char*)&OkHeader, sizeof(OkHeader), 0);
}

void SendError(SOCKET ClientSocket)
{
    MESSAGE_HEADER ErrHeader = { ERR, 0 };
    send(ClientSocket, (char*)&ErrHeader, sizeof(ErrHeader), 0);
}

int ThreadFunc(SOCKET ClientSocket)
{
    void* MsgData = NULL;
    void* Config = NULL;
    void* Payload = NULL;
    MESSAGE_HEADER Header = { OK, 0 };

    while (Header.Type != QUIT)
    {
        {
            unsigned hdrSize = (unsigned)sizeof(Header);
            int rv = recv(ClientSocket, (char*)&Header, hdrSize, MSG_WAITALL);
            if (rv != sizeof(Header))
            {
                if (rv == SOCKET_ERROR)
                {
                    if (WSAGetLastError() == 10053)
                    {
                        printf("[+] Client disconnected\n");
                    }
                    else {
                        printf("[!] Error: recv(%u) failed: %d\n", hdrSize, WSAGetLastError());
                    }
                }
                else if (rv == 0)
                {
                    printf("[!] Socket closed during recv(%u)\n", hdrSize);
                }
                else
                {
                    printf("[!] Error: Unexpected receive length %d (expected %u)\n", rv, hdrSize);
                }
                SendError(ClientSocket);
                goto cleanup;
            }
        }

        // receive rest of message
        if (Header.Length)
        {
            MsgData = malloc(Header.Length);
            if (MsgData == NULL)
            {
                printf("[!] Error: MsgBuf Allocation Failed: %d\n", GetLastError());
                SendError(ClientSocket);
                goto cleanup;
            }
            int rv = recv(ClientSocket, (char*)MsgData, Header.Length, MSG_WAITALL);
            if ((unsigned)rv != Header.Length)
            {
                if (rv == SOCKET_ERROR)
                {
                    printf("[!] Error: recv(%u) failed: %d\n", Header.Length, WSAGetLastError());
                }
                else if (rv == 0)
                {
                    printf("[!] Socket closed during recv(%u)\n", Header.Length);
                }
                else
                {
                    printf("[!] Error: Unexpected receive length %d (expected %u)\n", rv, Header.Length);
                }
                SendError(ClientSocket);
                goto cleanup;
            }
        }

        // process message
        switch (Header.Type)
        {
        case CONFIG:
            if (Config)
            {
                free(Config);
            }
            // just move allocated buffer to Config
            Config = MsgData;
            MsgData = NULL;
            printf("[+] Config received (%u bytes)\n", Header.Length);
            break;
        case PAYLOAD:
            if (!Header.Length || (Config == NULL))
            {
                printf("[!] Error: Payload length is 0 (%d) or no config (%p)\n", Header.Length, Config);
                SendError(ClientSocket);
                goto cleanup;
            }
            if (Payload)
            {
                VirtualFree(Payload, 0, MEM_RELEASE);
            }
            Payload = VirtualAlloc(NULL, Header.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (Payload == NULL)
            {
                printf("[!] Error: Payload Allocation Failed: %d\n", GetLastError());
                SendError(ClientSocket);
                goto cleanup;
            }
            memcpy(Payload, MsgData, Header.Length);
            free(MsgData);
            MsgData = NULL;
            printf("[+] Payload received (%u bytes)\n", Header.Length);
            //if (DumpPayload(Payload, Header.Length))
            //{
            //    printf("[+] Payload saved to payload_debug.bin\n");
            //}
            break;
        case EXEC:
            if (Payload == NULL)
            {
                printf("[!] Error: Payload NULL at EXEC\n");
                SendError(ClientSocket);
                goto cleanup;
            }
            printf("[+] Executing Payload\n");
            ((void (*)(void*))Payload)(Config);
            break;
        case QUIT:
            break;
        default:
            SendError(ClientSocket);
            goto cleanup;
        }

        SendOk(ClientSocket);
        free(MsgData);
        MsgData = NULL;
    }
cleanup:

    if (MsgData)
    {
        free(MsgData);
    }
    if (Config)
    {
        free(Config);
    }
    //commented this out because the PIC should do this already. Plus it was causing the thread to crash
    //if (Payload)
    //{
    //    VirtualFree(Payload, 0, MEM_RELEASE);
    //}
    closesocket(ClientSocket);
    return 0;
}

int main()
{
    printf("[+] Initializing Winsock...\n");
    WSADATA wsaData = { 0 };
    int error = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (error)
    {
        return -1;
    }

    printf("[+] Binding to port %u\n", PORT_NUM);
    SOCKET ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ListenSocket == INVALID_SOCKET)
    {
        WSACleanup();
        return -1;
    }

    sockaddr_in service;
    service.sin_family = AF_INET;
    service.sin_port = htons(PORT_NUM);
    service.sin_addr.s_addr = INADDR_ANY;

    error = bind(ListenSocket, (SOCKADDR*)&service, sizeof(SOCKADDR));
    if (error == SOCKET_ERROR)
    {
        closesocket(ListenSocket);
        WSACleanup();
        return -1;
    }

    while (true)
    {
        printf("[+] Listening for connection...\n");
        error = listen(ListenSocket, 1);
        if (error == SOCKET_ERROR)
        {
            closesocket(ListenSocket);
            WSACleanup();
            return -1;
        }

        printf("[+] Accepting new connection...\n");
        SOCKET AcceptSocket = accept(ListenSocket, NULL, NULL);
        if (AcceptSocket == INVALID_SOCKET)
        {
            closesocket(ListenSocket);
            WSACleanup();
            return -1;
        }

        printf("[+] Client connected! Spawning new thread...\n");
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadFunc, (void*)AcceptSocket, 0, NULL);
    }

    closesocket(ListenSocket);
    WSACleanup();
    return 0;
}

