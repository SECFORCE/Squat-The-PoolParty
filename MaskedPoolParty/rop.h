#pragma once
#include <windows.h>

typedef struct
{
	PVOID pSetEvent;
	PVOID hEvent;
	PVOID pRcxGadget;
	PVOID addRspGadget;
	PVOID pNtContinue;
	PVOID pCtxVirtualProtectRX;
	PVOID pSystemFunction32;
	PVOID pKey;
	PVOID pPopRdxGadget;
	PVOID pImage;
	PVOID pSleepEx;
	PVOID bAlertable;
	PVOID dwMilliseconds;
	PVOID retGadget;
	PVOID pCtxVirtualProtectRW;
	PVOID pCtxTrigger;
	PVOID pPopRsp;

} ROPPER, *PROPPER;

EXTERN_C PVOID setup_rop(PVOID dummy, PROPPER params);