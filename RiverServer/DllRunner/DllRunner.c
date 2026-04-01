// DllRunner.c : Load and keep a DLL alive so its DllMain can run.
// Assumes driver is already loaded externally.
#include <windows.h>
#include <stdio.h>
#include <conio.h>

enum {
    LEECH_SINGLE_STATE_INIT = 0,
    LEECH_SINGLE_STATE_ATTACH = 1,
    LEECH_SINGLE_STATE_THREAD_STARTING = 2,
    LEECH_SINGLE_STATE_THREAD_RUNNING = 3,
    LEECH_SINGLE_STATE_THREAD_EXITED = 4
};

#define ORD_LEECH_SINGLE_DLL_GET_STATUS 21

typedef BOOL (WINAPI *PFN_LeechSingleDll_GetStatus)(DWORD *pdwState, DWORD *pdwThreadExitCode);

static void GetExeDir(wchar_t *outDir, size_t cchOutDir)
{
    wchar_t path[MAX_PATH] = { 0 };
    size_t i;
    if(!GetModuleFileNameW(NULL, path, (DWORD)_countof(path))) {
        outDir[0] = L'\0';
        return;
    }
    for(i = wcslen(path); i > 0; i--) {
        if(path[i - 1] == L'\\' || path[i - 1] == L'/') {
            path[i] = L'\0';
            break;
        }
    }
    wcsncpy_s(outDir, cchOutDir, path, _TRUNCATE);
}

static void EnsureConsole(void)
{
    FILE *fp;
    if(!GetConsoleWindow()) {
        AllocConsole();
    }
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);
    freopen_s(&fp, "CONIN$", "r", stdin);
    SetConsoleTitleW(L"DllRunner");
}

int wmain(int argc, wchar_t *argv[])
{
    HMODULE hDll;
    wchar_t dllPath[MAX_PATH] = { 0 };
    wchar_t dirPath[MAX_PATH] = { 0 };
    int i;
    int fNoWait = 0;
    PFN_LeechSingleDll_GetStatus pfnGetStatus = NULL;
    DWORD lastState = 0xffffffff;
    DWORD state = 0;
    DWORD exitCode = 0;

    EnsureConsole();

    for(i = 1; i < argc; i++) {
        if(0 == _wcsicmp(argv[i], L"/nowait")) {
            fNoWait = 1;
        } else if(dllPath[0] == L'\0') {
            wcsncpy_s(dllPath, _countof(dllPath), argv[i], _TRUNCATE);
        }
    }

    if(dllPath[0] == L'\0') {
        GetExeDir(dirPath, _countof(dirPath));
        _snwprintf_s(dllPath, _countof(dllPath), _TRUNCATE, L"%sRiverServerSingleDll.dll", dirPath);
    }

    hDll = LoadLibraryW(dllPath);
    if(!hDll) {
        DWORD gle = GetLastError();
        fwprintf(stderr, L"DllRunner: LoadLibrary failed: %s (GLE=0x%08x)\n", dllPath, gle);
        wprintf(L"DllRunner: Press ENTER to exit...\n");
        (void)getchar();
        return 1;
    }

    pfnGetStatus = (PFN_LeechSingleDll_GetStatus)GetProcAddress(hDll, (LPCSTR)(ULONG_PTR)ORD_LEECH_SINGLE_DLL_GET_STATUS);
    wprintf(L"DllRunner: Loaded %s\n", dllPath);
    if(fNoWait) {
        FreeLibrary(hDll);
        return 0;
    }

    wprintf(L"DllRunner: Press 'q' to unload and exit...\n");
    for(;;) {
        if(pfnGetStatus && pfnGetStatus(&state, &exitCode)) {
            if(state != lastState) {
                lastState = state;
                wprintf(L"DllRunner: DLL state=%lu exit=0x%08x\n", state, exitCode);
            }
        }
        if(_kbhit()) {
            int ch = _getch();
            if(ch == 'q' || ch == 'Q' || ch == 27) {
                break;
            }
        }
        Sleep(500);
    }
    FreeLibrary(hDll);
    return 0;
}
