// single_dll_main.c : entry point for the single-DLL LeechAgent/LeechCore build.
//
// This DLL auto-starts the LeechAgent in interactive TCP message transport mode.
//
#include <windows.h>
#include "leechagent.h"
#include "leechagent_svc.h"
#include "river_activation.h"

#ifndef LOAD_LIBRARY_SEARCH_DEFAULT_DIRS
#define LOAD_LIBRARY_SEARCH_DEFAULT_DIRS 0x00001000
#endif
#ifndef LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR
#define LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR 0x00000100
#endif

VOID LcAttach();
VOID LcDetach();

enum {
    LEECH_SINGLE_STATE_INIT = 0,
    LEECH_SINGLE_STATE_ATTACH = 1,
    LEECH_SINGLE_STATE_THREAD_STARTING = 2,
    LEECH_SINGLE_STATE_THREAD_RUNNING = 3,
    LEECH_SINGLE_STATE_THREAD_EXITED = 4
};

static LONG g_LeechAgentStarted = 0;
static HANDLE g_hLeechAgentThread = NULL;
static volatile LONG g_LeechSingleState = LEECH_SINGLE_STATE_INIT;
static volatile DWORD g_LeechSingleThreadExitCode = 0;

static VOID LeechSingleDll_SetDllSearchPath(_In_ HMODULE hModule)
{
    WCHAR wszPath[MAX_PATH] = { 0 };
    WCHAR *pSlash = NULL;
    if(!GetModuleFileNameW(hModule, wszPath, _countof(wszPath))) {
        return;
    }
    pSlash = wcsrchr(wszPath, L'\\');
    if(!pSlash) {
        return;
    }
    *(pSlash + 1) = L'\0';
    SetDllDirectoryW(wszPath);
    {
        HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
        if(hKernel) {
            typedef BOOL (WINAPI *PFN_SetDefaultDllDirectories)(DWORD);
            typedef DLL_DIRECTORY_COOKIE (WINAPI *PFN_AddDllDirectory)(PCWSTR);
            PFN_SetDefaultDllDirectories pfnSetDefaultDllDirectories =
                (PFN_SetDefaultDllDirectories)GetProcAddress(hKernel, "SetDefaultDllDirectories");
            PFN_AddDllDirectory pfnAddDllDirectory =
                (PFN_AddDllDirectory)GetProcAddress(hKernel, "AddDllDirectory");
            if(pfnSetDefaultDllDirectories) {
                pfnSetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR);
            }
            if(pfnAddDllDirectory) {
                pfnAddDllDirectory(wszPath);
            }
        }
    }
}

static DWORD WINAPI LeechSingleDll_LeechAgentThread(_In_ LPVOID lpParameter)
{
    LEECHSVC_CONFIG cfg;
    UNREFERENCED_PARAMETER(lpParameter);
    if(!Activation_Initialize()) {
        g_LeechSingleThreadExitCode = ERROR_ACCESS_DENIED;
        g_LeechSingleState = LEECH_SINGLE_STATE_THREAD_EXITED;
        return ERROR_ACCESS_DENIED;
    }
    ZeroMemory(&cfg, sizeof(cfg));
    cfg.fInteractive = TRUE;
    cfg.fInsecure = TRUE;
    cfg.fMSRPC = FALSE;
    cfg.fgRPC = FALSE;
    cfg.fHTTP = TRUE;
    wcscpy_s(cfg.wszTcpPortMSRPC, _countof(cfg.wszTcpPortMSRPC), LEECHSVC_TCP_PORT_MSRPC);
    wcscpy_s(cfg.wszTcpPortGRPC, _countof(cfg.wszTcpPortGRPC), LEECHSVC_TCP_PORT_GRPC);
    wcscpy_s(cfg.wszTcpPortHTTP, _countof(cfg.wszTcpPortHTTP), LEECHSVC_TCP_PORT_HTTP);
    strcpy_s(cfg.grpc.szListenAddress, _countof(cfg.grpc.szListenAddress), "0.0.0.0");
    g_LeechAgent_IsService = FALSE;
    g_LeechSingleState = LEECH_SINGLE_STATE_THREAD_RUNNING;
    LeechSvc_Interactive(&cfg);
    g_LeechSingleThreadExitCode = 0;
    g_LeechSingleState = LEECH_SINGLE_STATE_THREAD_EXITED;
    return 0;
}

BOOL WINAPI LeechSingleDll_GetStatus(_Out_opt_ DWORD *pdwState, _Out_opt_ DWORD *pdwThreadExitCode)
{
    if(pdwState) {
        *pdwState = (DWORD)g_LeechSingleState;
    }
    if(pdwThreadExitCode) {
        *pdwThreadExitCode = g_LeechSingleThreadExitCode;
    }
    return TRUE;
}

BOOL WINAPI DllMain(_In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_ PVOID lpvReserved)
{
    if(fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        g_LeechSingleState = LEECH_SINGLE_STATE_ATTACH;
        LcAttach();
        LeechSingleDll_SetDllSearchPath(hinstDLL);
        if(InterlockedCompareExchange(&g_LeechAgentStarted, 1, 0) == 0) {
            g_LeechSingleState = LEECH_SINGLE_STATE_THREAD_STARTING;
            g_hLeechAgentThread = CreateThread(NULL, 0, LeechSingleDll_LeechAgentThread, NULL, 0, NULL);
            if(!g_hLeechAgentThread) {
                g_LeechSingleThreadExitCode = GetLastError();
                g_LeechSingleState = LEECH_SINGLE_STATE_THREAD_EXITED;
            }
        }
    } else if(fdwReason == DLL_PROCESS_DETACH) {
        Activation_Shutdown();
        LcDetach();
    }
    return TRUE;
}


