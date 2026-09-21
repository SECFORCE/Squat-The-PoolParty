#include <windows.h>
#include "syscalls.h"


NTSTATUS w_ZwAssociateWaitCompletionPacket(
	HANDLE WaitCopmletionPacketHandle,
	HANDLE IoCompletionHandle,
	HANDLE TargetObjectHandle,
	PVOID KeyContext,
	PVOID ApcContext,
	NTSTATUS IoStatus,
	ULONG_PTR IoStatusInformation,
	PBOOLEAN AlreadySignaled
)
{
	ZwAssociateWaitCompletionPacket_t pZwAssociateWaitCompletionPacket = (ZwAssociateWaitCompletionPacket_t) GetProcAddress(GetModuleHandleA("ntdll"), "ZwAssociateWaitCompletionPacket");
	if (pZwAssociateWaitCompletionPacket == NULL)
	{
		printf("Error resolving pZwAssociateWaitCompletionPacket\n");
		return -1;
	}
	return pZwAssociateWaitCompletionPacket(
		WaitCopmletionPacketHandle,
		IoCompletionHandle,
		TargetObjectHandle,
		KeyContext,
		ApcContext,
		IoStatus,
		IoStatusInformation,
		AlreadySignaled);
}