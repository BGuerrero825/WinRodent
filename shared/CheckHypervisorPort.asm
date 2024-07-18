;;
; Checks if hypervisor port is being used
;
; @return 1 if hypervisor port is in use; 0 otherwise

PUBLIC CheckHypervisorPort

_TEXT SEGMENT

CheckHypervisorPort PROC

    push   rdx
    push   rcx
    push   rbx

    ; IN is an assembly language opcode that reads input from a port specified by
    ;   DX register.

    xor     ebx, ebx        ;
    mov     ecx, 0000000ah  ; GetVersionAction (10d), command to be run
    mov     eax, "VMXh"     ; VMXh, "magic number" at port
    mov     edx, "VX"       ; VX, move the VMware port number into edx

    in      eax, dx         ; call the in instruction

    mov     eax, "VMXh"     ; VMXh, "magic number" at port
    cmp     eax, ebx        ; compare returned port value to magic

    ; the following opcode sets al to true (1) or false (0) based on the zero/equal flag to make setting
    ;       the return value easy
    setz    al              ; set return value

    pop    rbx
    pop    rcx
    pop    rdx

    ret
CheckHypervisorPort ENDP

_TEXT ENDS

END
