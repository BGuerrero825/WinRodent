def ror(dword, bits):
    '''Implement 32-bit Rotate Right'''
    return (dword >> bits | dword << (32 - bits)) & 0xFFFFFFFF

def unicode(string, uppercase=True):
    '''Convert a string to 16-bit Unicode, upper-case'''
    result = ''
    if uppercase:
        string = string.upper()
    for c in string:
        result += c + '\x00'
    return result

def myhash(module, function, bits=13, print_hash=True):
    '''Calculate the hash value of a given symbol in a module'''
    module_hash = 0
    function_hash = 0
    for c in unicode(module + '\x00'):
        module_hash = ror(module_hash, bits)
        module_hash += ord(c)
    for c in str(function + '\x00'):
        function_hash = ror(function_hash, bits)
        function_hash += ord(c)
    h = module_hash + function_hash & 0xFFFFFFFF
    if print_hash:
        print('[+] 0x%08X = %s!%s' % (h, module.lower(), function))
    return h


# Example usage
if __name__ == '__main__':
    ntdll = ['RtlAllocateHeap', 'DbgPrint', 'RtlGetVersion']
    for f in ntdll:
        myhash('ntdll.dll', f)

    kernel32 = ['LoadLibraryA', 'GetProcAddress', 'HeapFree', 'GetProcessHeap', 'HeapReAlloc', 'CreateFileA', 'WriteFile', 'CloseHandle', 'GetFileSize', 'CreateToolhelp32Snapshot', 'Process32First', 'Process32Next', 'GetCurrentProcessId']
    for f in kernel32:
        myhash('kernel32.dll', f)

    winsock = ['WSAStartup', 'WSACleanup', 'socket', 'closesocket', 'connect', 'send', 'recv', 'WSAGetLastError']
    for f in winsock:
        myhash('ws2_32.dll', f)

    msvcrt = ['_snprintf']
    for f in msvcrt:
        myhash('msvcrt.dll', f)
