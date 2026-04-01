// util.c : implementation of various utility functions.
//
// (c) Ulf Frisk, 2018-2026
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "util.h"
#include <stdarg.h>

#ifdef _WIN32
static INIT_ONCE g_UtilLogInitOnce = INIT_ONCE_STATIC_INIT;
static CRITICAL_SECTION g_UtilLogLock;
static BOOL g_fUtilLogLockInitialized = FALSE;
static CHAR g_szUtilLogFile[MAX_PATH] = { 0 };
static CHAR g_szUtilLogUpstreamFile[MAX_PATH] = { 0 };
static CHAR g_szUtilLogKernelDiagFile[MAX_PATH] = { 0 };

static BOOL CALLBACK Util_LogInit(_In_ PINIT_ONCE InitOnce, _In_opt_ PVOID Parameter, _Out_opt_ PVOID *Context)
{
    CHAR szExePath[MAX_PATH] = { 0 };
    CHAR *pSlash;
    UNREFERENCED_PARAMETER(InitOnce);
    UNREFERENCED_PARAMETER(Parameter);
    UNREFERENCED_PARAMETER(Context);
    if(!GetModuleFileNameA(NULL, szExePath, MAX_PATH - 1)) {
        return FALSE;
    }
    pSlash = strrchr(szExePath, '\\');
    if(!pSlash) {
        pSlash = strrchr(szExePath, '/');
    }
    if(pSlash) {
        pSlash[1] = 0;
    } else {
        strcpy_s(szExePath, sizeof(szExePath), ".\\");
    }
    _snprintf_s(g_szUtilLogFile, sizeof(g_szUtilLogFile), _TRUNCATE, "%sriverclientlog", szExePath);
    CreateDirectoryA(g_szUtilLogFile, NULL);
    _snprintf_s(g_szUtilLogFile, sizeof(g_szUtilLogFile), _TRUNCATE, "%sriverclientlog\\riverclient.log", szExePath);
    _snprintf_s(g_szUtilLogUpstreamFile, sizeof(g_szUtilLogUpstreamFile), _TRUNCATE, "%sriverclientlog\\riverclient_upstream.log", szExePath);
    _snprintf_s(g_szUtilLogKernelDiagFile, sizeof(g_szUtilLogKernelDiagFile), _TRUNCATE, "%sriverclientlog\\riverclient_kernelbase.log", szExePath);
    InitializeCriticalSection(&g_UtilLogLock);
    g_fUtilLogLockInitialized = TRUE;
    return TRUE;
}
#endif /* _WIN32 */

/*
* Retrieve the operating system path of the directory which is containing this:
* .dll/.so file.
* -- szPath
*/
VOID Util_GetPathLib(_Out_writes_(MAX_PATH) PCHAR szPath)
{
    SIZE_T i;
    ZeroMemory(szPath, MAX_PATH);
#ifdef _WIN32
    HMODULE hModuleLeechCore;
    hModuleLeechCore = LoadLibraryA("leechcore.dll");
    GetModuleFileNameA(hModuleLeechCore, szPath, MAX_PATH - 4);
    if(hModuleLeechCore) { FreeLibrary(hModuleLeechCore); }
#endif /* _WIN32 */
#if defined(LINUX) || defined(MACOS)
    Dl_info Info = { 0 };
    if(!dladdr((void *)Util_GetPathLib, &Info) || !Info.dli_fname) { return; }
    strncpy(szPath, Info.dli_fname, MAX_PATH - 1);
#endif /* LINUX || MACOS */
    for(i = strlen(szPath) - 1; i > 0; i--) {
        if(szPath[i] == '/' || szPath[i] == '\\') {
            szPath[i + 1] = '\0';
            return;
        }
    }
}

static VOID Util_LogFilePathV(_In_z_ const CHAR *szPath, _In_z_ _Printf_format_string_ char const *const _Format, va_list ap)
{
#ifdef _WIN32
    HANDLE hFile;
    DWORD cbWritten = 0;
    SYSTEMTIME st = { 0 };
    CHAR szPrefix[96] = { 0 };
    CHAR szMessage[4096] = { 0 };
    va_list apCopy;
    if(!szPath || !szPath[0]) {
        return;
    }
    if(!InitOnceExecuteOnce(&g_UtilLogInitOnce, Util_LogInit, NULL, NULL) || !g_fUtilLogLockInitialized) {
        return;
    }
    GetLocalTime(&st);
    _snprintf_s(
        szPrefix,
        sizeof(szPrefix),
        _TRUNCATE,
        "[%04u-%02u-%02u %02u:%02u:%02u.%03u][pid=%lu][tid=%lu] ",
        st.wYear,
        st.wMonth,
        st.wDay,
        st.wHour,
        st.wMinute,
        st.wSecond,
        st.wMilliseconds,
        GetCurrentProcessId(),
        GetCurrentThreadId());
    va_copy(apCopy, ap);
    _vsnprintf_s(szMessage, sizeof(szMessage), _TRUNCATE, _Format, apCopy);
    va_end(apCopy);
    EnterCriticalSection(&g_UtilLogLock);
    hFile = CreateFileA(szPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile != INVALID_HANDLE_VALUE) {
        WriteFile(hFile, szPrefix, (DWORD)strlen(szPrefix), &cbWritten, NULL);
        WriteFile(hFile, szMessage, (DWORD)strlen(szMessage), &cbWritten, NULL);
        if(szMessage[0] && (szMessage[strlen(szMessage) - 1] != '\n')) {
            static const CHAR szNewline[] = "\r\n";
            WriteFile(hFile, szNewline, (DWORD)sizeof(szNewline) - 1, &cbWritten, NULL);
        }
        CloseHandle(hFile);
    }
    LeaveCriticalSection(&g_UtilLogLock);
#else
    UNREFERENCED_PARAMETER(szPath);
    UNREFERENCED_PARAMETER(_Format);
    UNREFERENCED_PARAMETER(ap);
#endif
}

VOID Util_LogFileA(_In_z_ _Printf_format_string_ char const *const _Format, ...)
{
#ifdef _WIN32
    va_list ap;
    if(!InitOnceExecuteOnce(&g_UtilLogInitOnce, Util_LogInit, NULL, NULL) || !g_fUtilLogLockInitialized || !g_szUtilLogFile[0]) {
        return;
    }
    va_start(ap, _Format);
    Util_LogFilePathV(g_szUtilLogFile, _Format, ap);
    va_end(ap);
#else
    UNREFERENCED_PARAMETER(_Format);
#endif
}

VOID Util_LogUpstreamA(_In_z_ _Printf_format_string_ char const *const _Format, ...)
{
#ifdef _WIN32
    va_list ap;
    if(!InitOnceExecuteOnce(&g_UtilLogInitOnce, Util_LogInit, NULL, NULL) || !g_fUtilLogLockInitialized || !g_szUtilLogUpstreamFile[0]) {
        return;
    }
    va_start(ap, _Format);
    Util_LogFilePathV(g_szUtilLogUpstreamFile, _Format, ap);
    va_end(ap);
#else
    UNREFERENCED_PARAMETER(_Format);
#endif
}

VOID Util_LogKernelDiagA(_In_z_ _Printf_format_string_ char const *const _Format, ...)
{
#ifdef _WIN32
    va_list ap;
    if(!InitOnceExecuteOnce(&g_UtilLogInitOnce, Util_LogInit, NULL, NULL) || !g_fUtilLogLockInitialized || !g_szUtilLogKernelDiagFile[0]) {
        return;
    }
    va_start(ap, _Format);
    Util_LogFilePathV(g_szUtilLogKernelDiagFile, _Format, ap);
    va_end(ap);
#else
    UNREFERENCED_PARAMETER(_Format);
#endif
}

/*
* Try retrieve a numerical value from sz. If sz starts with '0x' it will be
* interpreted as hex (base 16), otherwise decimal (base 10).
* -- sz
* -- return
*/
QWORD Util_GetNumericA(_In_ LPSTR sz)
{
    BOOL fhex = sz[0] && sz[1] && (sz[0] == '0') && ((sz[1] == 'x') || (sz[1] == 'X'));
    return strtoull(sz, NULL, fhex ? 16 : 10);
}

//-----------------------------------------------------------------------------

#define Util_2HexChar(x) (((((x) & 0xf) <= 9) ? '0' : ('a' - 10)) + ((x) & 0xf))

#define UTIL_PRINTASCII \
    "................................ !\"#$%&'()*+,-./0123456789:;<=>?" \
    "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ " \
    "................................................................" \
    "................................................................" \

BOOL Util_FillHexAscii(_In_ PBYTE pb, _In_ DWORD cb, _In_ DWORD cbInitialOffset, _Inout_opt_ LPSTR sz, _Inout_ PDWORD pcsz)
{
    DWORD i, j, o = 0, iMod, cRows;
    // checks
    if((cbInitialOffset > cb) || (cbInitialOffset > 0x1000) || (cbInitialOffset & 0xf)) { return FALSE; }
    cRows = (cb + 0xf) >> 4;
    if(!sz) {
        *pcsz = 1 + cRows * 76;
        return TRUE;
    }
    if(!pb || (*pcsz <= cRows * 76)) { return FALSE; }
    // fill buffer with bytes
    for(i = cbInitialOffset; i < cb + ((cb % 16) ? (16 - cb % 16) : 0); i++)
    {
        // address
        if(0 == i % 16) {
            iMod = i % 0x10000;
            sz[o++] = Util_2HexChar(iMod >> 12);
            sz[o++] = Util_2HexChar(iMod >> 8);
            sz[o++] = Util_2HexChar(iMod >> 4);
            sz[o++] = Util_2HexChar(iMod);
            sz[o++] = ' ';
            sz[o++] = ' ';
            sz[o++] = ' ';
            sz[o++] = ' ';
        } else if(0 == i % 8) {
            sz[o++] = ' ';
        }
        // hex
        if(i < cb) {
            sz[o++] = Util_2HexChar(pb[i] >> 4);
            sz[o++] = Util_2HexChar(pb[i]);
            sz[o++] = ' ';
        } else {
            sz[o++] = ' ';
            sz[o++] = ' ';
            sz[o++] = ' ';
        }
        // ascii
        if(15 == i % 16) {
            sz[o++] = ' ';
            sz[o++] = ' ';
            for(j = i - 15; j <= i; j++) {
                if(j >= cb) {
                    sz[o++] = ' ';
                } else {
                    sz[o++] = UTIL_PRINTASCII[pb[j]];
                }
            }
            sz[o++] = '\n';
        }
    }
    sz[o] = 0;
    *pcsz = o;
    return TRUE;
}

VOID Util_PrintHexAscii(_In_opt_ PLC_CONTEXT ctxLC, _In_ PBYTE pb, _In_ DWORD cb, _In_ DWORD cbInitialOffset)
{
    DWORD szMax = 0;
    LPSTR sz;
    if(cb > 0x10000) {
        if(ctxLC) {
            lcprintf(ctxLC, "Large output. Only displaying first 65kB.\n");
        } else {
            printf("Large output. Only displaying first 65kB.\n");
        }
        cb = 0x10000 - cbInitialOffset;
    }
    Util_FillHexAscii(pb, cb, cbInitialOffset, NULL, &szMax);
    if(!(sz = LocalAlloc(0, szMax))) { return; }
    Util_FillHexAscii(pb, cb, cbInitialOffset, sz, &szMax);
    if(ctxLC) {
        lcprintf(ctxLC, "%s", sz);
    } else {
        printf("%s", sz);
    }
    LocalFree(sz);
}

VOID Util_SplitN(_In_ LPSTR sz, _In_ CHAR chDelimiter, _In_ DWORD cpsz, _Out_writes_(MAX_PATH) PCHAR _szBuf, _Inout_ LPSTR *psz)
{
    DWORD i, j;
    strcpy_s(_szBuf, MAX_PATH, sz);
    psz[0] = _szBuf;
    for(i = 1; i < cpsz; i++) {
        psz[i] = "";
    }
    for(i = 0, j = 0; i < MAX_PATH; i++) {
        if('\0' == _szBuf[i]) {
            return;
        }
        if(chDelimiter == _szBuf[i]) {
            j++;
            if(j >= cpsz) {
                return;
            }
            _szBuf[i] = '\0';
            psz[j] = _szBuf + i + 1;
        }
    }
}

VOID Util_Split2(_In_ LPSTR sz, _In_ CHAR chDelimiter, _Out_writes_(MAX_PATH) PCHAR _szBuf, _Out_ LPSTR *psz1, _Out_ LPSTR *psz2)
{
    LPSTR psz[2] = { 0 };
    Util_SplitN(sz, chDelimiter, 2, _szBuf, psz);
    *psz1 = psz[0];
    *psz2 = psz[1];
}

VOID Util_Split3(_In_ LPSTR sz, _In_ CHAR chDelimiter, _Out_writes_(MAX_PATH) PCHAR _szBuf, _Out_ LPSTR *psz1, _Out_ LPSTR *psz2, _Out_ LPSTR *psz3)
{
    LPSTR psz[3] = { 0 };
    Util_SplitN(sz, chDelimiter, 3, _szBuf, psz);
    *psz1 = psz[0];
    *psz2 = psz[1];
    *psz3 = psz[2];
}

VOID Util_GenRandom(_Out_ PBYTE pb, _In_ DWORD cb)
{
    DWORD i = 0;
    srand((unsigned int)GetTickCount64());
    if(cb % 2) {
        *(PBYTE)(pb) = (BYTE)rand();
        i++;
    }
    for(; i <= cb - 2; i += 2) {
        *(PWORD)(pb + i) = (WORD)rand();
    }
}

BOOL Util_IsPlatformBitness64()
{
    BOOL fWow64 = TRUE;
    if(Util_IsProgramBitness64()) {
        return TRUE;
    }
    IsWow64Process(GetCurrentProcess(), &fWow64);
    return fWow64;
}

BOOL Util_IsProgramBitness64()
{
#ifndef _WIN64
    return FALSE;
#endif /* _WIN64 */
    return TRUE;
}
