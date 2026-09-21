/*
* Author: Dimitri Di Cristofaro (GlenX) - @d_glenx
* This project is a PoC that shows PoolParty process injection technique 
* with the addition of an helper stub that allows to not crash the target process after the shellcode returns
* 
* This code is part of the talk "Squat The PoolParty" made at BEACON 2026
* https://github.com/SECFORCE/Squat-The-PoolParty
*/

#include <windows.h>
#include <stdio.h>

#include "PoolPartyC.h"


#ifdef EXE
int main(int argc, char** argv)
{

    int pid = 0;
    if (argc > 1)
    {
        pid = atoi(argv[1]);
    }
    else
    {
        printf("Usage %s [PID]\n", argv[0]);
    }
    _main(pid);
    getchar();
    return 0;
}
#endif

#ifndef EXE
//extern "C" {
__declspec(dllexport) void entry() {
    int pid = 1580;
    _main(pid);

}
//}


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
#endif

