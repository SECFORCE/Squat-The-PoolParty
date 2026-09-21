#include <windows.h>
#include <stdio.h>
#include "winapi.h"

LPVOID w_VirtualAllocEx(HANDLE hTargetPid, SIZE_T szSizeOfChunk, DWORD dwAllocationType, DWORD dwProtect)
{
	LPVOID AllocatedMemory = VirtualAllocEx(hTargetPid, NULL, szSizeOfChunk, dwAllocationType, dwProtect);
	if (AllocatedMemory == NULL)
	{
		printf("Error : 0x%x\n", GetLastError());
	}
	return AllocatedMemory;
}

BOOL w_WriteProcessMemory(HANDLE hTargetPid, LPVOID AllocatedMemory, LPVOID pBuffer, SIZE_T szSizeOfBuffer)
{
	SIZE_T lpNumberOfBytesWritten = 0;
	BOOL success = TRUE;
	success = WriteProcessMemory(
		hTargetPid,
		AllocatedMemory,
		pBuffer,
		szSizeOfBuffer,
		&lpNumberOfBytesWritten);
	
	if (!success)
	{
		printf("WriteProcessMemmory - Something went wrong! LastError : 0x%x\n", GetLastError());
	}

	if (lpNumberOfBytesWritten != szSizeOfBuffer)
	{
		printf("Bytes written: %d\n", lpNumberOfBytesWritten);
	}
	return success;
}




HANDLE w_CreateEvent(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitalState, LPWSTR lpName)
{
	HANDLE hEvent = CreateEvent(
		lpEventAttributes,
		bManualReset,
		bInitalState,
		lpName);

	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		printf("WARNING: The event `%S` already exists\n", lpName);
	}

	return hEvent;
}


BOOL w_SetEvent(HANDLE hEvent)
{
	return SetEvent(
		hEvent
	);
}
