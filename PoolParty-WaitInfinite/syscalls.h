#pragma once
/*
EXTERN_C
NTSTATUS NTAPI ZwAssociateWaitCompletionPacket(
	_In_ HANDLE 		WaitCompletionPacketHandle,
	_In_ HANDLE 		IoCompletionHandle,
	_In_ HANDLE 		TargetObjectHandle,
	_In_opt_ PVOID 		KeyContext,
	_In_opt_ PVOID 		ApcContext,
	_In_ NTSTATUS 		IoStatus,
	_In_ ULONG_PTR 		IoStatusInformation,
	_Out_opt_ PBOOLEAN 	AlreadySignaled
);
*/

#define STATUS_SUCCESS 0


typedef NTSTATUS(WINAPI* ZwAssociateWaitCompletionPacket_t)(
	_In_ HANDLE 		WaitCompletionPacketHandle,
	_In_ HANDLE 		IoCompletionHandle,
	_In_ HANDLE 		TargetObjectHandle,
	_In_opt_ PVOID 		KeyContext,
	_In_opt_ PVOID 		ApcContext,
	_In_ NTSTATUS 		IoStatus,
	_In_ ULONG_PTR 		IoStatusInformation,
	_Out_opt_ PBOOLEAN 	AlreadySignaled
);


NTSTATUS w_ZwAssociateWaitCompletionPacket(
	HANDLE WaitCopmletionPacketHandle,
	HANDLE IoCompletionHandle,
	HANDLE TargetObjectHandle,
	PVOID KeyContext,
	PVOID ApcContext,
	NTSTATUS IoStatus,
	ULONG_PTR IoStatusInformation,
	PBOOLEAN AlreadySignaled
);