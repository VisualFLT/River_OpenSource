// device_pmem.c : implementation of the rekall winpmem memory acquisition device.
//
// (c) Ulf Frisk, 2018-2026
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "leechcore.h"
#include "leechcore_device.h"
#include "leechcore_internal.h"
#include "util.h"
#ifdef _WIN32
DWORD g_cDevicePMEM = 0;
static BOOL g_fDevicePMEM_OwnedDriver = FALSE;
static UINT64 g_pmemNonce = 1;
#ifndef DEVICEPMEM_LOCAL_LOG_ENABLE
#define DEVICEPMEM_LOCAL_LOG_ENABLE 0
#endif
static VOID PmemLogFile(_In_z_ _Printf_format_string_ char const* const _Format, ...)
{
#if !DEVICEPMEM_LOCAL_LOG_ENABLE
    UNREFERENCED_PARAMETER(_Format);
    return;
#else
    CHAR szBuffer[0x400] = { 0 };
    CHAR szLine[0x500] = { 0 };
    SYSTEMTIME st = { 0 };
    va_list argptr;
    GetLocalTime(&st);
    va_start(argptr, _Format);
    _vsnprintf_s(szBuffer, _countof(szBuffer), _TRUNCATE, _Format, argptr);
    va_end(argptr);
    _snprintf_s(szLine, _countof(szLine), _TRUNCATE, "[%04u-%02u-%02u %02u:%02u:%02u.%03u] %s",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, szBuffer);
#ifdef _WIN32
    CreateDirectoryA("C:\\pmem_log", NULL);
#endif
    FILE *f = NULL;
    if(!fopen_s(&f, "C:\\pmem_log\\pmem.log", "a")) {
        fputs(szLine, f);
        fputs("\n", f);
        fclose(f);
    }
#endif
}
//-----------------------------------------------------------------------------
// MEMORY INFO STRUCT FROM WINPMEM HEADER BELOW:
// https://github.com/Velocidex/WinPmem/blob/master/kernel/userspace_interface/winpmem_shared.h
//-----------------------------------------------------------------------------
#pragma pack(push, 2)
#define PMEM_MODE_IOSPACE   0
#define PMEM_MODE_PHYSICAL  1
#define PMEM_MODE_PTE       2
#define PMEM_MODE_AUTO      99
#define NUMBER_OF_RUNS      (100) // must match driver winpmem_shared.h
#define IOCTL_PMEM_DEVICE_TYPE      0x8330
#define PMEM_CTRL_IOCTRL        CTL_CODE(IOCTL_PMEM_DEVICE_TYPE, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)
#define PMEM_WRITE_ENABLE       CTL_CODE(IOCTL_PMEM_DEVICE_TYPE, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)
#define PMEM_INFO_IOCTRL        CTL_CODE(IOCTL_PMEM_DEVICE_TYPE, 0x803, METHOD_NEITHER, FILE_ANY_ACCESS)
typedef struct tdPHYSICAL_MEMORY_RANGE {
    __int64 start;
    __int64 length;
} PHYSICAL_MEMORY_RANGE;
struct PmemMemoryInfo {
    LARGE_INTEGER CR3;
    LARGE_INTEGER NtBuildNumber;
    LARGE_INTEGER KernBase;
    LARGE_INTEGER KDBG;
#ifdef _WIN64
    LARGE_INTEGER KPCR[64];
#else
    LARGE_INTEGER KPCR[32];
#endif
    LARGE_INTEGER PfnDataBase;
    LARGE_INTEGER PsLoadedModuleList;
    LARGE_INTEGER PsActiveProcessHead;
    LARGE_INTEGER NtBuildNumberAddr;
    LARGE_INTEGER Padding[0xfe];
    LARGE_INTEGER NumberOfRuns;
    PHYSICAL_MEMORY_RANGE Run[NUMBER_OF_RUNS];
};
#pragma pack(pop)
//-----------------------------------------------------------------------------
// OTHER (NON WINPMEM) TYPEDEFS AND DEFINES BELOW:
//-----------------------------------------------------------------------------
#define DEVICEPMEM_SERVICENAME           "AvastSvc"
#define DEVICEPMEM_NAME_MAX              32
#define DEVICEPMEM_NAME_LEN              12
typedef struct tdDEVICE_CONTEXT_PMEM {
    HANDLE hFile;
    QWORD paMax;
    struct PmemMemoryInfo MemoryInfo;
} DEVICE_CONTEXT_PMEM, *PDEVICE_CONTEXT_PMEM;

// ---------------- PMEM IOCTL encryption (PSK + nonce) ----------------
#define PMEM_PSK_K0 0x9e3779b97f4a7c15ULL
#define PMEM_PSK_K1 0x3c6ef372fe94f82bULL
typedef struct _PMEM_ENC_HEADER {
    UINT64 Nonce;
    UINT32 DataLen;
    UINT32 Mac;
} PMEM_ENC_HEADER;
#define PMEM_ENC_OVERHEAD (sizeof(PMEM_ENC_HEADER))

static __forceinline UINT64 rotl64(UINT64 x, int b) { return (x << b) | (x >> (64 - b)); }
static UINT64 siphash24(const BYTE *msg, size_t len, UINT64 k0, UINT64 k1)
{
    UINT64 v0 = 0x736f6d6570736575ULL ^ k0;
    UINT64 v1 = 0x646f72616e646f6dULL ^ k1;
    UINT64 v2 = 0x6c7967656e657261ULL ^ k0;
    UINT64 v3 = 0x7465646279746573ULL ^ k1;
    size_t i = 0;
    while (i + 8 <= len) {
        UINT64 m = 0;
        for (int j = 0; j < 8; j++) m |= ((UINT64)msg[i + j]) << (8 * j);
        v3 ^= m;
        for (int r = 0; r < 2; r++) {
            v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32);
            v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2; v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0; v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32);
        }
        v0 ^= m; i += 8;
    }
    UINT64 b = ((UINT64)len) << 56;
    size_t left = len - i;
    for (size_t j = 0; j < left; j++) b |= ((UINT64)msg[i + j]) << (8 * j);
    v3 ^= b;
    for (int r = 0; r < 2; r++) {
        v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32);
        v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2; v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0; v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32);
    }
    v0 ^= b; v2 ^= 0xff;
    for (int r = 0; r < 4; r++) {
        v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32);
        v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2; v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0; v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32);
    }
    return v0 ^ v1 ^ v2 ^ v3;
}
static __forceinline UINT32 pmem_mac32(UINT64 nonce, UINT32 dataLen, const BYTE *plain)
{
    PMEM_ENC_HEADER hdr = { nonce, dataLen, 0 };
    UINT64 mac = siphash24((BYTE*)&hdr, sizeof(hdr), PMEM_PSK_K0, PMEM_PSK_K1);
    if (dataLen) mac = siphash24(plain, dataLen, mac, PMEM_PSK_K1);
    return (UINT32)(mac & 0xffffffff);
}
static VOID pmem_xor(BYTE *dst, const BYTE *src, SIZE_T len, UINT64 nonce)
{
    UINT64 ctr = 0;
    while (len) {
        BYTE seed[16];
        memcpy(seed, &nonce, sizeof(UINT64));
        memcpy(seed + sizeof(UINT64), &ctr, sizeof(UINT64));
        UINT64 ks = siphash24(seed, sizeof(seed), PMEM_PSK_K0, PMEM_PSK_K1);
        SIZE_T chunk = (len > sizeof(UINT64)) ? sizeof(UINT64) : len;
        for (SIZE_T i = 0; i < chunk; i++) dst[i] = src[i] ^ ((BYTE*)&ks)[i];
        dst += chunk; src += chunk; len -= chunk; ctr++;
    }
}
static BOOL pmem_encrypt(const BYTE *plain, DWORD plainLen, UINT64 nonce, BYTE **ppOut, DWORD *pOutLen)
{
    DWORD need = PMEM_ENC_OVERHEAD + plainLen;
    BYTE *buf = (BYTE*)LocalAlloc(LMEM_FIXED, need);
    if (!buf) return FALSE;
    PMEM_ENC_HEADER *h = (PMEM_ENC_HEADER*)buf;
    h->Nonce = nonce;
    h->DataLen = plainLen;
    h->Mac = pmem_mac32(nonce, plainLen, plain);
    if (plainLen) {
        pmem_xor(buf + PMEM_ENC_OVERHEAD, plain, plainLen, nonce);
    }
    *ppOut = buf;
    *pOutLen = need;
    return TRUE;
}
static BOOL pmem_decrypt(const BYTE *enc, DWORD encLen, UINT64 expectedNonce, BYTE **ppPlain, DWORD *pPlainLen)
{
    if (!enc || encLen < PMEM_ENC_OVERHEAD) return FALSE;
    const PMEM_ENC_HEADER *h = (const PMEM_ENC_HEADER*)enc;
    if (h->Nonce != expectedNonce) return FALSE;
    if (h->DataLen != encLen - PMEM_ENC_OVERHEAD) return FALSE;
    DWORD len = h->DataLen;
    BYTE *plain = NULL;
    if (len) {
        plain = (BYTE*)LocalAlloc(LMEM_FIXED, len);
        if (!plain) return FALSE;
        pmem_xor(plain, enc + PMEM_ENC_OVERHEAD, len, h->Nonce);
    }
    UINT32 mac = pmem_mac32(h->Nonce, len, len ? plain : NULL);
    if (mac != h->Mac) { if (plain) LocalFree(plain); return FALSE; }
    *ppPlain = plain;
    *pPlainLen = len;
    g_pmemNonce++; // sync with driver advance
    return TRUE;
}
//-----------------------------------------------------------------------------
// GENERAL FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------
static ULONGLONG DevicePMEM_Mix64(_In_ ULONGLONG value)
{
    value ^= value >> 33;
    value *= 0xff51afd7ed558ccdULL;
    value ^= value >> 33;
    value *= 0xc4ceb9fe1a85ec53ULL;
    value ^= value >> 33;
    return value;
}
static VOID DevicePMEM_GenerateNameA(_Out_writes_(cchName) CHAR *pszName, _In_ size_t cchName)
{
    SYSTEMTIME st = { 0 };
    ULONGLONG seed, state;
    const char alphabet[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    int i;
    if(!pszName || (cchName < (DEVICEPMEM_NAME_LEN + 1))) {
        return;
    }
    GetSystemTime(&st);
    seed = (((ULONGLONG)st.wYear) << 48) |
           (((ULONGLONG)st.wMonth) << 40) |
           (((ULONGLONG)st.wDay) << 32) |
           (((ULONGLONG)st.wHour) << 24);
    seed ^= 0xC3A5C85C97CB3127ULL;
    state = DevicePMEM_Mix64(seed);
    pszName[0] = 'k';
    pszName[1] = 'x';
    for(i = 2; i < DEVICEPMEM_NAME_LEN; i++) {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state *= 0x2545F4914F6CDD1DULL;
        pszName[i] = alphabet[state & 31];
    }
    pszName[DEVICEPMEM_NAME_LEN] = '\0';
}
static VOID DevicePMEM_BuildDynamicPaths(
    _Out_writes_(cchName) CHAR *pszName,
    _In_ size_t cchName,
    _Out_writes_(cchGlobal) CHAR *pszGlobal,
    _In_ size_t cchGlobal,
    _Out_writes_(cchDos) CHAR *pszDos,
    _In_ size_t cchDos)
{
    static CHAR s_PmemName[DEVICEPMEM_NAME_MAX] = { 0 };
    static BOOL s_PmemNameReady = FALSE;
    if(!s_PmemNameReady) {
        DevicePMEM_GenerateNameA(s_PmemName, _countof(s_PmemName));
        s_PmemNameReady = TRUE;
        PmemLogFile("PMEM: device name generated: %s", s_PmemName);
    }
    strncpy_s(pszName, cchName, s_PmemName, _TRUNCATE);
    _snprintf_s(pszGlobal, cchGlobal, _TRUNCATE, "\\\\.\\\\GLOBALROOT\\\\Device\\\\%s", pszName);
    _snprintf_s(pszDos, cchDos, _TRUNCATE, "\\\\.\\\\%s", pszName);
}

static HANDLE DevicePMEM_OpenDeviceHandle(_Out_opt_ LPCSTR *ppszPath)
{
    static CHAR szLastPath[MAX_PATH] = { 0 };
    CHAR szName[DEVICEPMEM_NAME_MAX] = { 0 };
    CHAR szPathGlobal[MAX_PATH] = { 0 };
    CHAR szPathDos[MAX_PATH] = { 0 };
    LPCSTR szPaths[] = {
        szPathGlobal,
        szPathDos
    };
    DWORD i;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    if(ppszPath) { *ppszPath = NULL; }
    DevicePMEM_BuildDynamicPaths(szName, _countof(szName), szPathGlobal, _countof(szPathGlobal), szPathDos, _countof(szPathDos));
    for(i = 0; i < _countof(szPaths); i++) {
        strncpy_s(szLastPath, _countof(szLastPath), szPaths[i], _TRUNCATE);
        hFile = CreateFileA(
            szPaths[i],
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
        if(hFile != INVALID_HANDLE_VALUE) {
            if(ppszPath) { *ppszPath = szLastPath; }
            return hFile;
        }
    }
    if(ppszPath && szLastPath[0]) { *ppszPath = szLastPath; }
    return INVALID_HANDLE_VALUE;
}
VOID DevicePMEM_ReadScatter(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cpMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    PDEVICE_CONTEXT_PMEM ctx = (PDEVICE_CONTEXT_PMEM)ctxLC->hDevice;
    DWORD i, cbRead;
    PMEM_SCATTER pMEM;
    LARGE_INTEGER qwA_LI;
    for(i = 0; i < cpMEMs; i++) {
        pMEM = ppMEMs[i];
        if(pMEM->f || MEM_SCATTER_ADDR_ISINVALID(pMEM)) { continue; }
        qwA_LI.QuadPart = pMEM->qwA;
        SetFilePointerEx(ctx->hFile, qwA_LI, NULL, FILE_BEGIN);
        pMEM->f = ReadFile(ctx->hFile, pMEM->pb, pMEM->cb, &cbRead, NULL);
        if(pMEM->f) {
            if(ctxLC->fPrintf[LC_PRINTF_VVV]) {
                lcprintf_fn(
                    ctxLC,
                    "READ:\n        offset=%016llx req_len=%08x\n",
                    pMEM->qwA,
                    pMEM->cb
                );
                Util_PrintHexAscii(ctxLC, pMEM->pb, pMEM->cb, 0);
            }
        } else {
            lcprintfvvv_fn(ctxLC, "READ FAILED:\n        offset=%016llx req_len=%08x\n", pMEM->qwA, pMEM->cb);
            PmemLogFile("READ FAILED offset=0x%016llx len=0x%08x", pMEM->qwA, pMEM->cb);
        }
    }
}
/*
* Unload the winpmem kernel driver and also delete the driver-loading service.
*/
VOID DevicePMEM_SvcClose()
{
    SC_HANDLE hSCM, hSvcPMem;
    SERVICE_STATUS SvcStatus;
    // 1: shut down and delete service.
    if((hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE))) {
        hSvcPMem = OpenServiceA(hSCM, DEVICEPMEM_SERVICENAME, SERVICE_ALL_ACCESS);
        if(hSvcPMem) {
            ControlService(hSvcPMem, SERVICE_CONTROL_STOP, &SvcStatus);
        };
        if(hSvcPMem) { DeleteService(hSvcPMem); }
        if(hSvcPMem) { CloseServiceHandle(hSvcPMem); }
        CloseServiceHandle(hSCM);
    }
}
/*
* Is pmem service running (kernel driver loaded).
*/
BOOL DevicePMEM_SvcStatusRunning(_In_ PLC_CONTEXT ctxLC)
{
    PDEVICE_CONTEXT_PMEM ctx = (PDEVICE_CONTEXT_PMEM)ctxLC->hDevice;
    BOOL fResult = FALSE;
    BOOL fServicePresent = FALSE;
    SC_HANDLE hSCM, hSvcPMem;
    LPCSTR pszPath = NULL;
    // 1: check if driver is already loaded
    if((hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE))) {
        if((hSvcPMem = OpenServiceA(hSCM, DEVICEPMEM_SERVICENAME, SERVICE_ALL_ACCESS))) {
            if(hSvcPMem) { CloseServiceHandle(hSvcPMem); }
            fServicePresent = TRUE;
        }
        CloseServiceHandle(hSCM);
    }
    // 2: attempt to open device handle (allow bypass SCM check).
    ctx->hFile = DevicePMEM_OpenDeviceHandle(&pszPath);
    fResult = (ctx->hFile != INVALID_HANDLE_VALUE);
    PmemLogFile(
        "PMEM driver check: service=%s open=%s path=%s gle=0x%08x",
        fServicePresent ? "present" : "absent",
        fResult ? "ok" : "fail",
        pszPath ? pszPath : "(none)",
        fResult ? 0 : GetLastError());
    return fResult;
}
/*
* Create the winpmem kernel driver loader service and load the kernel driver
* into the kernel. Upon fail it's guaranteed that no lingering service exists.
*/
_Success_(return)
BOOL DevicePMEM_SvcStart(_In_ PLC_CONTEXT ctxLC)
{
    PDEVICE_CONTEXT_PMEM ctx = (PDEVICE_CONTEXT_PMEM)ctxLC->hDevice;
    DWORD i, dwWinErr;
    CHAR szDriverFile[MAX_PATH] = { 0 };
    FILE *pDriverFile = NULL;
    SC_HANDLE hSCM = 0, hSvcPMem = 0;
    BOOL f64;
    // ????????????????????????????????
    {
        LPCSTR pszPath = NULL;
        ctx->hFile = DevicePMEM_OpenDeviceHandle(&pszPath);
        if(ctx->hFile == INVALID_HANDLE_VALUE) {
            PmemLogFile("PMEM: CreateFile failed path=%s gle=0x%08x", pszPath ? pszPath : "(none)", GetLastError());
            return FALSE;
        }
    }
    g_fDevicePMEM_OwnedDriver = FALSE;
    PmemLogFile("PMEM: Handle opened successfully (driver preloaded).");
    return TRUE;
}
/*
* Close the PMEM device and clean up both context and any kernel drivers.
*/
VOID DevicePMEM_Close(_Inout_ PLC_CONTEXT ctxLC)
{
    PDEVICE_CONTEXT_PMEM ctx = (PDEVICE_CONTEXT_PMEM)ctxLC->hDevice;
    if(0 == --g_cDevicePMEM && g_fDevicePMEM_OwnedDriver) {
        DevicePMEM_SvcClose();
    }
    if(ctx) {
        CloseHandle(ctx->hFile);
        LocalFree(ctx);
    }
    ctxLC->hDevice = 0;
}
_Success_(return)
BOOL DevicePMEM_GetMemoryInformation(_Inout_ PLC_CONTEXT ctxLC, _In_ BOOL fFirst)
{
    PDEVICE_CONTEXT_PMEM ctx = (PDEVICE_CONTEXT_PMEM)ctxLC->hDevice;
    DWORD i, cbRead, dwMode = PMEM_MODE_PTE;
    BYTE *req = NULL, *resp = NULL, *plain = NULL;
    DWORD reqLen = 0, respLen = PMEM_ENC_OVERHEAD + sizeof(ctx->MemoryInfo), plainLen = 0;
    UINT64 nonce = g_pmemNonce;
    // 1: build encrypted request (empty payload) and retrieve info
    if(!pmem_encrypt(NULL, 0, nonce, &req, &reqLen)) { return FALSE; }
    resp = (BYTE*)LocalAlloc(LMEM_FIXED, respLen);
    if(!resp) { LocalFree(req); return FALSE; }
    if(!DeviceIoControl(ctx->hFile, PMEM_INFO_IOCTRL, req, reqLen, resp, respLen, &cbRead, NULL)) {
        if(!fFirst) lcprintf(ctxLC, "DEVICE: ERROR: Unable to communicate with winpmem driver.\n");
        PmemLogFile("PMEM: PMEM_INFO_IOCTRL failed gle=0x%08x cbRead=%u", GetLastError(), cbRead);
        LocalFree(req); LocalFree(resp);
        return FALSE;
    }
    LocalFree(req); req = NULL;
    if(!pmem_decrypt(resp, cbRead, nonce, &plain, &plainLen)) {
        PmemLogFile("PMEM: decrypt PMEM_INFO response failed");
        LocalFree(resp);
        return FALSE;
    }
    LocalFree(resp); resp = NULL;
    if(plainLen != sizeof(ctx->MemoryInfo)) {
        PmemLogFile("PMEM: invalid PMEM_INFO plaintext length=%u", plainLen);
        if(plain) LocalFree(plain);
        return FALSE;
    }
    memcpy(&ctx->MemoryInfo, plain, sizeof(ctx->MemoryInfo));
    if(plain) LocalFree(plain);
    // 2: sanity checks
    if((ctx->MemoryInfo.NumberOfRuns.QuadPart == 0) || (ctx->MemoryInfo.NumberOfRuns.QuadPart > 100)) {
        if(!fFirst) {
            lcprintf(ctxLC, "DEVICE: ERROR: too few/many memory segments reported from winpmem driver. (%lli)\n", ctx->MemoryInfo.NumberOfRuns.QuadPart);
        }
        PmemLogFile("PMEM: Invalid NumberOfRuns=%lli", ctx->MemoryInfo.NumberOfRuns.QuadPart);
        return FALSE;
    }
    // 3: parse memory ranges
    for(i = 0; i < ctx->MemoryInfo.NumberOfRuns.QuadPart; i++) {
        if(!LcMemMap_AddRange(ctxLC, ctx->MemoryInfo.Run[i].start, ctx->MemoryInfo.Run[i].length, ctx->MemoryInfo.Run[i].start)) {
            if(!fFirst) {
                lcprintf(ctxLC, "DEVICE: FAIL: unable to add range to memory map. (%016llx %016llx %016llx)\n", ctx->MemoryInfo.Run[i].start, ctx->MemoryInfo.Run[i].length, ctx->MemoryInfo.Run[i].start);
            }
            PmemLogFile("PMEM: AddRange failed start=0x%016llx len=0x%016llx", ctx->MemoryInfo.Run[i].start, ctx->MemoryInfo.Run[i].length);
            return FALSE;
        }
    }
    // 4: try preferred acquisition modes in order, staying in nonce sync.
    {
        DWORD modes[] = { PMEM_MODE_PTE, PMEM_MODE_PHYSICAL, PMEM_MODE_IOSPACE };
        BOOL modeSet = FALSE;
        for (int i = 0; i < (int)(sizeof(modes) / sizeof(modes[0])); i++) {
            dwMode = modes[i];
            nonce = g_pmemNonce;
            req = NULL; reqLen = 0;
            if(!pmem_encrypt((BYTE*)&dwMode, sizeof(DWORD), nonce, &req, &reqLen)) {
                break;
            }
            if(DeviceIoControl(ctx->hFile, PMEM_CTRL_IOCTRL, req, reqLen, NULL, 0, &cbRead, NULL)) {
                modeSet = TRUE;
                LocalFree(req);
                g_pmemNonce++; // driver increments after successful decrypt
                break;
            }
            // driver already advanced nonce when decrypt succeeded, keep in sync
            g_pmemNonce++;
            PmemLogFile("PMEM: PMEM_CTRL_IOCTRL mode=%u failed gle=0x%08x", dwMode, GetLastError());
            LocalFree(req);
        }
        if(!modeSet) {
            return FALSE;
        }
    }
    return TRUE;
}
_Success_(return)
BOOL DevicePMEM_GetOption(_In_ PLC_CONTEXT ctxLC, _In_ QWORD fOption, _Out_ PQWORD pqwValue)
{
    PDEVICE_CONTEXT_PMEM ctx = (PDEVICE_CONTEXT_PMEM)ctxLC->hDevice;
    if(fOption == LC_OPT_MEMORYINFO_VALID) {
        *pqwValue = 1;
        return TRUE;
    }
    switch(fOption) {
        case LC_OPT_MEMORYINFO_FLAG_32BIT:
            *pqwValue = 0; // only 64-bit supported currently
            return TRUE;
        case LC_OPT_MEMORYINFO_FLAG_PAE:
            *pqwValue = 0;
            return TRUE;
        case LC_OPT_MEMORYINFO_ARCH:
            *pqwValue = 3;
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_VERSION_MINOR:
            *pqwValue = ctx->MemoryInfo.NtBuildNumber.HighPart;
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_VERSION_MAJOR:
            *pqwValue = ctx->MemoryInfo.NtBuildNumber.LowPart;
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_DTB:
            *pqwValue = ctx->MemoryInfo.CR3.QuadPart;
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_PFN:
            *pqwValue = ctx->MemoryInfo.PfnDataBase.QuadPart;
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_PsLoadedModuleList:
            *pqwValue = ctx->MemoryInfo.PsLoadedModuleList.QuadPart;
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_PsActiveProcessHead:
            *pqwValue = ctx->MemoryInfo.PsActiveProcessHead.QuadPart;
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_MACHINE_IMAGE_TP:
            *pqwValue = 0x8664; // only 64-bit supported currently
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_KERNELBASE:
            *pqwValue = ctx->MemoryInfo.KernBase.QuadPart;
            return TRUE;
    }
    *pqwValue = 0;
    return FALSE;
}
_Success_(return)
BOOL DevicePMEM_Open2(_Inout_ PLC_CONTEXT ctxLC, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo, _In_ BOOL fFirst)
{
    BOOL result;
    PDEVICE_CONTEXT_PMEM ctx;
    if(ppLcCreateErrorInfo) { *ppLcCreateErrorInfo = NULL; }
    PmemLogFile("PMEM: Open start (fFirst=%d)", fFirst);
    g_pmemNonce = 1; // reset nonce for new session
    // 1: initialize core context.
    ctx = (PDEVICE_CONTEXT_PMEM)LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_CONTEXT_PMEM));
    if(!ctx) { return FALSE; }
    ctxLC->hDevice = (HANDLE)ctx;
    // set callback functions and fix up config
    ctxLC->Config.fVolatile = TRUE;
    ctxLC->pfnClose = DevicePMEM_Close;
    ctxLC->pfnReadScatter = DevicePMEM_ReadScatter;
    ctxLC->pfnGetOption = DevicePMEM_GetOption;
    // 2: open existing winpmem kernel driver (loading handled externally).
    g_cDevicePMEM++;
    result = DevicePMEM_SvcStatusRunning(ctxLC);
    if(!result) { PmemLogFile("PMEM: driver not running"); }
    // 3: retrieve memory map.
    result = result && DevicePMEM_GetMemoryInformation(ctxLC, fFirst);
    if(!result) {
        DevicePMEM_Close(ctxLC);
        PmemLogFile("PMEM: Open failed after memory info");
        return FALSE;
    }
    lcprintfv(ctxLC, "DEVICE: Successfully loaded winpmem memory acquisition driver.\n");
    PmemLogFile("PMEM: Open success");
    return TRUE;
}
_Success_(return)
BOOL DevicePMEM_Open(_Inout_ PLC_CONTEXT ctxLC, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo)
{
    // Sometimes communication with PMEM driver will fail even though the driver
    // is loaded. It's unknown why this is happening. But it always helps trying
    // again so wrap the open function to perform a retry if there is a fail.
    if(DevicePMEM_Open2(ctxLC, ppLcCreateErrorInfo, TRUE)) { return TRUE; }
    Sleep(100);
    return DevicePMEM_Open2(ctxLC, ppLcCreateErrorInfo, FALSE);
}
#endif /* _WIN32 */
#if defined(LINUX) || defined(MACOS)
_Success_(return)
BOOL DevicePMEM_Open(_Inout_ PLC_CONTEXT ctxLC, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo)
{
    lcprintfv(ctxLC, "DEVICE: FAIL: 'pmem' memory acquisition only supported on Windows.\n");
    if(ppLcCreateErrorInfo) { *ppLcCreateErrorInfo = NULL; }
    return FALSE;
}
#endif /* LINUX || MACOS */








