#pragma once
#include <windows.h>


BOOL w_WriteProcessMemory(HANDLE hTargetPid, LPVOID AllocatedMemory, LPVOID pBuffer, SIZE_T szSizeOfBuffer);
LPVOID w_VirtualAllocEx(HANDLE hTargetPid, SIZE_T szSizeOfChunk, DWORD dwAllocationType, DWORD dwProtect);
HANDLE w_CreateEvent(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitalState, LPWSTR lpName);
BOOL w_SetEvent(HANDLE hEvent);