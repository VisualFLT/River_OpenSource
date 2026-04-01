#include "river_activation.h"

#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")

#ifndef RIVER_ACTIVATION_BYPASS
#define RIVER_ACTIVATION_BYPASS 0
#endif

#define RIVER_ACTIVATION_DEFAULT_HOST             L"velvetvoid.club"
#define RIVER_ACTIVATION_DEFAULT_PORT             443
#define RIVER_ACTIVATION_PATH_CHALLENGE           L"/api/v1/challenge"
#define RIVER_ACTIVATION_PATH_ACTIVATE            L"/api/v1/activate"
#define RIVER_ACTIVATION_USER_AGENT               L"RiverServerSingleDll/0.5"
#define RIVER_ACTIVATION_PRODUCT                  "RiverServerSingleDll"
#define RIVER_ACTIVATION_KEY_ID                   "RIVER-KEY-001"
#define RIVER_ACTIVATION_PRIVATE_BLOB_FILE        "RIVER-KEY-001.private.blob"
#define RIVER_ACTIVATION_REG_VALUE_KEY_ID         "KeyId"
#define RIVER_ACTIVATION_REG_VALUE_PRIVATE_BLOB   "PrivateKeyBlob"
#define RIVER_ACTIVATION_REG_VALUE_SERVER_HOST    "ServerHost"
#define RIVER_ACTIVATION_REG_VALUE_SERVER_PORT    "ServerPort"
#define RIVER_ACTIVATION_REG_VALUE_SERVER_USE_HTTPS "ServerUseHttps"
#define RIVER_ACTIVATION_REG_VALUE_SERVER_IGNORE_CERT_ERRORS "ServerIgnoreCertErrors"
#define RIVER_ACTIVATION_REG_VALUE_STATUS         "Status"
#define RIVER_ACTIVATION_REG_PATH_NAME_LEN        18
#define RIVER_ACTIVATION_REG_PATH_HOURS_BACK      1
#define RIVER_ACTIVATION_REG_PATH_ALPHABET        "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
#define RIVER_ACTIVATION_REG_PATH_SEED_XOR        0xC3A5C85C97CB3127ui64
#define RIVER_ACTIVATION_REG_PATH_XORSHIFT_MULT   0x2545F4914F6CDD1Dui64
#define RIVER_ACTIVATION_REG_PATH_HOUR_TICKS      36000000000ui64

#define RIVER_ACTIVATION_STATUS_PENDING           0
#define RIVER_ACTIVATION_STATUS_AUTHORIZED        1
#define RIVER_ACTIVATION_STATUS_DENIED            2

#define RIVER_ACTIVATION_DEFAULT_TTL_SEC          300
#define RIVER_ACTIVATION_MIN_TTL_SEC              30
#define RIVER_ACTIVATION_MAX_TTL_SEC              3600
#define RIVER_ACTIVATION_RETRY_INTERVAL_MS        5000

static WCHAR g_wszActivationHost[256] = RIVER_ACTIVATION_DEFAULT_HOST;
static INTERNET_PORT g_wActivationPort = RIVER_ACTIVATION_DEFAULT_PORT;
static BOOL g_fActivationUseHttps = TRUE;
static BOOL g_fActivationIgnoreCertErrors = FALSE;
#define RIVER_ACTIVATION_HOST g_wszActivationHost
#define RIVER_ACTIVATION_PORT g_wActivationPort

typedef struct tdRIVER_ACTIVATION_STATE {
    BOOL fLockInitialized;
    CRITICAL_SECTION Lock;
    BOOL fInitialized;
    BOOL fAuthorized;
    ULONGLONG qwExpireTickMs;
    ULONGLONG qwLastAttemptTickMs;
} RIVER_ACTIVATION_STATE, *PRIVER_ACTIVATION_STATE;

static RIVER_ACTIVATION_STATE g_RiverActivationState = { 0 };

static VOID Activation_LoadServerConfig();
static VOID Activation_WriteStatus(_In_ DWORD dwStatus);
static ULONGLONG Activation_Mix64(_In_ ULONGLONG v);
static ULONGLONG Activation_NextState(_In_ ULONGLONG state);
static BOOL Activation_GetRegistryUtcHour(_In_ DWORD dwHoursBack, _Out_ SYSTEMTIME* pstUtcHour);
static BOOL Activation_BuildRegistryPathForHoursBack(_In_ DWORD dwHoursBack, _Out_writes_(cchPath) LPSTR szPath, _In_ DWORD cchPath);

static ULONGLONG Activation_Mix64(_In_ ULONGLONG v)
{
    v ^= v >> 33;
    v *= 0xFF51AFD7ED558CCDui64;
    v ^= v >> 33;
    v *= 0xC4CEB9FE1A85EC53ui64;
    v ^= v >> 33;
    return v;
}

static ULONGLONG Activation_NextState(_In_ ULONGLONG state)
{
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    return state * RIVER_ACTIVATION_REG_PATH_XORSHIFT_MULT;
}

static BOOL Activation_GetRegistryUtcHour(_In_ DWORD dwHoursBack, _Out_ SYSTEMTIME* pstUtcHour)
{
    SYSTEMTIME stNow = { 0 };
    FILETIME ftNow = { 0 };
    ULARGE_INTEGER uli = { 0 };

    if(!pstUtcHour) {
        return FALSE;
    }

    GetSystemTime(&stNow);
    if(!SystemTimeToFileTime(&stNow, &ftNow)) {
        return FALSE;
    }

    uli.LowPart = ftNow.dwLowDateTime;
    uli.HighPart = ftNow.dwHighDateTime;
    uli.QuadPart -= ((ULONGLONG)dwHoursBack * RIVER_ACTIVATION_REG_PATH_HOUR_TICKS);
    ftNow.dwLowDateTime = uli.LowPart;
    ftNow.dwHighDateTime = uli.HighPart;
    if(!FileTimeToSystemTime(&ftNow, pstUtcHour)) {
        return FALSE;
    }

    pstUtcHour->wMinute = 0;
    pstUtcHour->wSecond = 0;
    pstUtcHour->wMilliseconds = 0;
    return TRUE;
}

static BOOL Activation_BuildRegistryPathForHoursBack(_In_ DWORD dwHoursBack, _Out_writes_(cchPath) LPSTR szPath, _In_ DWORD cchPath)
{
    SYSTEMTIME stUtcHour = { 0 };
    ULONGLONG seed, state;
    CHAR szName[RIVER_ACTIVATION_REG_PATH_NAME_LEN + 1] = { 0 };
    const CHAR* szAlphabet = RIVER_ACTIVATION_REG_PATH_ALPHABET;
    INT i;

    if(!szPath || cchPath < 32) {
        return FALSE;
    }
    szPath[0] = '\0';

    if(!Activation_GetRegistryUtcHour(dwHoursBack, &stUtcHour)) {
        return FALSE;
    }

    seed = ((ULONGLONG)stUtcHour.wYear << 48)
        | ((ULONGLONG)stUtcHour.wMonth << 40)
        | ((ULONGLONG)stUtcHour.wDay << 32)
        | ((ULONGLONG)stUtcHour.wHour << 24);
    state = Activation_Mix64(seed ^ RIVER_ACTIVATION_REG_PATH_SEED_XOR);

    for(i = 0; i < RIVER_ACTIVATION_REG_PATH_NAME_LEN; i++) {
        state = Activation_NextState(state);
        szName[i] = szAlphabet[state & 31];
    }
    szName[RIVER_ACTIVATION_REG_PATH_NAME_LEN] = '\0';

    _snprintf_s(
        szPath,
        cchPath,
        _TRUNCATE,
        "Software\\%.6s\\%.6s\\%.6s",
        szName,
        szName + 6,
        szName + 12
    );
    return szPath[0] != '\0';
}

static VOID Activation_ForceAuthorizedState(_In_ DWORD dwTtlSec)
{
    ULONGLONG qwNow = GetTickCount64();
    if(!g_RiverActivationState.fLockInitialized) {
        InitializeCriticalSection(&g_RiverActivationState.Lock);
        g_RiverActivationState.fLockInitialized = TRUE;
    }
    EnterCriticalSection(&g_RiverActivationState.Lock);
    g_RiverActivationState.fInitialized = TRUE;
    g_RiverActivationState.fAuthorized = TRUE;
    g_RiverActivationState.qwLastAttemptTickMs = qwNow;
    g_RiverActivationState.qwExpireTickMs = qwNow + ((ULONGLONG)dwTtlSec * 1000ULL);
    LeaveCriticalSection(&g_RiverActivationState.Lock);
    Activation_WriteStatus(RIVER_ACTIVATION_STATUS_AUTHORIZED);
}

static BOOL Activation_ParseBoolTrue(_In_z_ LPCSTR szBody, _In_z_ LPCSTR szKey)
{
    CHAR szPattern[64] = { 0 };
    _snprintf_s(szPattern, _countof(szPattern), _TRUNCATE, "\"%s\":true", szKey);
    if(strstr(szBody, szPattern)) {
        return TRUE;
    }
    _snprintf_s(szPattern, _countof(szPattern), _TRUNCATE, "\"%s\" : true", szKey);
    return strstr(szBody, szPattern) != NULL;
}

static DWORD Activation_ParseTtlSec(_In_z_ LPCSTR szBody)
{
    LPCSTR p = strstr(szBody, "\"ttl_sec\"");
    INT ttl = RIVER_ACTIVATION_DEFAULT_TTL_SEC;
    if(!p) { return RIVER_ACTIVATION_DEFAULT_TTL_SEC; }
    p = strchr(p, ':');
    if(!p) { return RIVER_ACTIVATION_DEFAULT_TTL_SEC; }
    p++;
    while(*p == ' ' || *p == '\t') { p++; }
    ttl = atoi(p);
    if(ttl < RIVER_ACTIVATION_MIN_TTL_SEC) {
        ttl = RIVER_ACTIVATION_MIN_TTL_SEC;
    } else if(ttl > RIVER_ACTIVATION_MAX_TTL_SEC) {
        ttl = RIVER_ACTIVATION_MAX_TTL_SEC;
    }
    return (DWORD)ttl;
}

static BOOL Activation_JsonGetString(_In_z_ LPCSTR szJson, _In_z_ LPCSTR szKey, _Out_writes_(cchOut) LPSTR szOut, _In_ DWORD cchOut)
{
    CHAR szPattern[64] = { 0 };
    LPCSTR p, pStart, pEnd;
    SIZE_T cch;
    szOut[0] = '\0';
    _snprintf_s(szPattern, _countof(szPattern), _TRUNCATE, "\"%s\"", szKey);
    p = strstr(szJson, szPattern);
    if(!p) { return FALSE; }
    p = strchr(p, ':');
    if(!p) { return FALSE; }
    p++;
    while(*p == ' ' || *p == '\t') { p++; }
    if(*p != '"') { return FALSE; }
    pStart = p + 1;
    pEnd = pStart;
    while(*pEnd) {
        if(*pEnd == '"' && *(pEnd - 1) != '\\') {
            break;
        }
        pEnd++;
    }
    if(*pEnd != '"') { return FALSE; }
    cch = pEnd - pStart;
    if(cch >= cchOut) { return FALSE; }
    memcpy(szOut, pStart, cch);
    szOut[cch] = '\0';
    return TRUE;
}

static VOID Activation_HexEncode(_In_reads_(cbData) const BYTE* pbData, _In_ DWORD cbData, _Out_writes_(cchOut) LPSTR szOut, _In_ DWORD cchOut)
{
    static const CHAR szHex[] = "0123456789abcdef";
    DWORD i;
    if(cchOut < (cbData * 2 + 1)) {
        szOut[0] = '\0';
        return;
    }
    for(i = 0; i < cbData; i++) {
        szOut[2 * i] = szHex[(pbData[i] >> 4) & 0x0f];
        szOut[2 * i + 1] = szHex[pbData[i] & 0x0f];
    }
    szOut[cbData * 2] = '\0';
}

static BOOL Activation_MakeMachineId(_Out_writes_(cchMachineId) LPSTR szMachineId, _In_ DWORD cchMachineId)
{
    CHAR szComputer[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
    CHAR szWindowsDir[MAX_PATH] = { 0 };
    CHAR szRoot[] = "C:\\";
    DWORD cchComputer = MAX_COMPUTERNAME_LENGTH + 1;
    DWORD dwSerial = 0;
    SYSTEM_INFO si = { 0 };

    if(!GetComputerNameA(szComputer, &cchComputer)) {
        strcpy_s(szComputer, sizeof(szComputer), "unknown");
    }
    if(GetWindowsDirectoryA(szWindowsDir, _countof(szWindowsDir)) && (strlen(szWindowsDir) >= 2) && (szWindowsDir[1] == ':')) {
        szRoot[0] = szWindowsDir[0];
    }
    GetVolumeInformationA(szRoot, NULL, 0, &dwSerial, NULL, NULL, NULL, 0);
    GetNativeSystemInfo(&si);

    _snprintf_s(
        szMachineId,
        cchMachineId,
        _TRUNCATE,
        "%s-%08X-%u",
        szComputer,
        dwSerial,
        (UINT)si.wProcessorArchitecture
    );
    return TRUE;
}

static BOOL Activation_GetModuleDirectoryA(_Out_writes_(cchOut) LPSTR szOut, _In_ DWORD cchOut)
{
    HMODULE hSelf = NULL;
    CHAR szPath[MAX_PATH] = { 0 };
    CHAR *pSlash;
    szOut[0] = '\0';
    if(!GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCSTR)&Activation_GetModuleDirectoryA,
        &hSelf)) {
        return FALSE;
    }
    if(!GetModuleFileNameA(hSelf, szPath, _countof(szPath))) {
        return FALSE;
    }
    pSlash = strrchr(szPath, '\\');
    if(!pSlash) { return FALSE; }
    *(pSlash + 1) = '\0';
    strncpy_s(szOut, cchOut, szPath, _TRUNCATE);
    return TRUE;
}

static BOOL Activation_LoadFile(_In_z_ LPCSTR szPath, _Out_ PBYTE* ppbData, _Out_ PDWORD pcbData)
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    LARGE_INTEGER liSize = { 0 };
    PBYTE pb = NULL;
    DWORD cbRead = 0;
    *ppbData = NULL;
    *pcbData = 0;
    hFile = CreateFileA(szPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == INVALID_HANDLE_VALUE) { return FALSE; }
    if(!GetFileSizeEx(hFile, &liSize) || liSize.QuadPart <= 0 || liSize.QuadPart > 0x7fffffff) {
        CloseHandle(hFile);
        return FALSE;
    }
    pb = (PBYTE)LocalAlloc(LMEM_FIXED, (SIZE_T)liSize.QuadPart);
    if(!pb) {
        CloseHandle(hFile);
        return FALSE;
    }
    if(!ReadFile(hFile, pb, (DWORD)liSize.QuadPart, &cbRead, NULL) || cbRead != (DWORD)liSize.QuadPart) {
        LocalFree(pb);
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);
    *ppbData = pb;
    *pcbData = cbRead;
    return TRUE;
}

static BOOL Activation_TryReadPrivateBlobFromOpenKey(_In_ HKEY hKey, _Out_ PBYTE* ppbBlob, _Out_ PDWORD pcbBlob)
{
    DWORD dwType = 0;
    DWORD cbBlob = 0;
    LONG lStatus = RegQueryValueExA(hKey, RIVER_ACTIVATION_REG_VALUE_PRIVATE_BLOB, NULL, &dwType, NULL, &cbBlob);
    if(lStatus != ERROR_SUCCESS || dwType != REG_BINARY || cbBlob == 0 || cbBlob >= 0x7fffffff) {
        return FALSE;
    }

    PBYTE pbBlob = (PBYTE)LocalAlloc(LMEM_FIXED, cbBlob);
    if(!pbBlob) {
        return FALSE;
    }

    DWORD cbRead = cbBlob;
    lStatus = RegQueryValueExA(hKey, RIVER_ACTIVATION_REG_VALUE_PRIVATE_BLOB, NULL, &dwType, pbBlob, &cbRead);
    if(lStatus == ERROR_SUCCESS && dwType == REG_BINARY && cbRead == cbBlob) {
        *ppbBlob = pbBlob;
        *pcbBlob = cbBlob;
        return TRUE;
    }

    SecureZeroMemory(pbBlob, cbBlob);
    LocalFree(pbBlob);
    return FALSE;
}

static BOOL Activation_LoadPrivateKeyBlob(_Out_ PBYTE* ppbBlob, _Out_ PDWORD pcbBlob)
{
    CHAR szDir[MAX_PATH] = { 0 };
    CHAR szPath[MAX_PATH] = { 0 };
    CHAR szRegPath[128] = { 0 };
    CHAR szSubKey[256] = { 0 };
    CHAR szUserActivationKey[512] = { 0 };
    HKEY hKey = NULL;
    DWORD dwIndex = 0;
    DWORD dwHoursBack = 0;
    DWORD cchSubKey = 0;
    LONG lStatus;
    const HKEY hRoots[1] = { HKEY_CURRENT_USER };
    INT i;

    *ppbBlob = NULL;
    *pcbBlob = 0;

    for(dwHoursBack = 0; dwHoursBack <= RIVER_ACTIVATION_REG_PATH_HOURS_BACK; dwHoursBack++) {
        if(!Activation_BuildRegistryPathForHoursBack(dwHoursBack, szRegPath, _countof(szRegPath))) {
            continue;
        }

        for(i = 0; i < _countof(hRoots); i++) {
            lStatus = RegOpenKeyExA(hRoots[i], szRegPath, 0, KEY_QUERY_VALUE, &hKey);
            if(lStatus == ERROR_SUCCESS) {
                if(Activation_TryReadPrivateBlobFromOpenKey(hKey, ppbBlob, pcbBlob)) {
                    RegCloseKey(hKey);
                    return TRUE;
                }
                RegCloseKey(hKey);
            }
        }
    }

    for(dwHoursBack = 0; dwHoursBack <= RIVER_ACTIVATION_REG_PATH_HOURS_BACK; dwHoursBack++) {
        if(!Activation_BuildRegistryPathForHoursBack(dwHoursBack, szRegPath, _countof(szRegPath))) {
            continue;
        }

        for(dwIndex = 0;; dwIndex++) {
            FILETIME ft = { 0 };
            cchSubKey = _countof(szSubKey);
            lStatus = RegEnumKeyExA(HKEY_USERS, dwIndex, szSubKey, &cchSubKey, NULL, NULL, NULL, &ft);
            if(lStatus != ERROR_SUCCESS) {
                break;
            }
            if(
                !_stricmp(szSubKey, ".DEFAULT") ||
                !_stricmp(szSubKey, "S-1-5-18") ||
                !_stricmp(szSubKey, "S-1-5-19") ||
                !_stricmp(szSubKey, "S-1-5-20") ||
                strstr(szSubKey, "_Classes")
            ) {
                continue;
            }
            _snprintf_s(szUserActivationKey, _countof(szUserActivationKey), _TRUNCATE, "%s\\%s", szSubKey, szRegPath);
            lStatus = RegOpenKeyExA(HKEY_USERS, szUserActivationKey, 0, KEY_QUERY_VALUE, &hKey);
            if(lStatus == ERROR_SUCCESS) {
                if(Activation_TryReadPrivateBlobFromOpenKey(hKey, ppbBlob, pcbBlob)) {
                    RegCloseKey(hKey);
                    return TRUE;
                }
                RegCloseKey(hKey);
            }
        }
    }

    // Fallback for legacy deployments.
    if(!Activation_GetModuleDirectoryA(szDir, _countof(szDir))) {
        return FALSE;
    }
    _snprintf_s(szPath, _countof(szPath), _TRUNCATE, "%s%s", szDir, RIVER_ACTIVATION_PRIVATE_BLOB_FILE);
    return Activation_LoadFile(szPath, ppbBlob, pcbBlob);
}

static BOOL Activation_TryReadKeyIdFromOpenKey(_In_ HKEY hKey, _Out_writes_(cchKeyId) LPSTR szKeyId, _In_ DWORD cchKeyId)
{
    DWORD dwType = REG_NONE;
    DWORD cbData = cchKeyId;
    LONG lStatus = RegQueryValueExA(hKey, RIVER_ACTIVATION_REG_VALUE_KEY_ID, NULL, &dwType, (LPBYTE)szKeyId, &cbData);
    if(lStatus != ERROR_SUCCESS || (dwType != REG_SZ && dwType != REG_EXPAND_SZ)) {
        return FALSE;
    }
    szKeyId[cchKeyId - 1] = '\0';
    return szKeyId[0] != '\0';
}

static VOID Activation_LoadKeyId(_Out_writes_(cchKeyId) LPSTR szKeyId, _In_ DWORD cchKeyId)
{
    CHAR szRegPath[128] = { 0 };
    CHAR szSubKey[256] = { 0 };
    CHAR szUserActivationKey[512] = { 0 };
    HKEY hKey = NULL;
    DWORD dwIndex = 0;
    DWORD dwHoursBack = 0;
    DWORD cchSubKey = 0;
    LONG lStatus;
    const HKEY hRoots[1] = { HKEY_CURRENT_USER };
    INT i;

    strncpy_s(szKeyId, cchKeyId, RIVER_ACTIVATION_KEY_ID, _TRUNCATE);

    for(dwHoursBack = 0; dwHoursBack <= RIVER_ACTIVATION_REG_PATH_HOURS_BACK; dwHoursBack++) {
        if(!Activation_BuildRegistryPathForHoursBack(dwHoursBack, szRegPath, _countof(szRegPath))) {
            continue;
        }

        for(i = 0; i < _countof(hRoots); i++) {
            lStatus = RegOpenKeyExA(hRoots[i], szRegPath, 0, KEY_QUERY_VALUE, &hKey);
            if(lStatus == ERROR_SUCCESS) {
                if(Activation_TryReadKeyIdFromOpenKey(hKey, szKeyId, cchKeyId)) {
                    RegCloseKey(hKey);
                    return;
                }
                RegCloseKey(hKey);
            }
        }
    }

    for(dwHoursBack = 0; dwHoursBack <= RIVER_ACTIVATION_REG_PATH_HOURS_BACK; dwHoursBack++) {
        if(!Activation_BuildRegistryPathForHoursBack(dwHoursBack, szRegPath, _countof(szRegPath))) {
            continue;
        }

        for(dwIndex = 0;; dwIndex++) {
            FILETIME ft = { 0 };
            cchSubKey = _countof(szSubKey);
            lStatus = RegEnumKeyExA(HKEY_USERS, dwIndex, szSubKey, &cchSubKey, NULL, NULL, NULL, &ft);
            if(lStatus != ERROR_SUCCESS) {
                break;
            }
            if(
                !_stricmp(szSubKey, ".DEFAULT") ||
                !_stricmp(szSubKey, "S-1-5-18") ||
                !_stricmp(szSubKey, "S-1-5-19") ||
                !_stricmp(szSubKey, "S-1-5-20") ||
                strstr(szSubKey, "_Classes")
            ) {
                continue;
            }
            _snprintf_s(szUserActivationKey, _countof(szUserActivationKey), _TRUNCATE, "%s\\%s", szSubKey, szRegPath);
            lStatus = RegOpenKeyExA(HKEY_USERS, szUserActivationKey, 0, KEY_QUERY_VALUE, &hKey);
            if(lStatus == ERROR_SUCCESS) {
                if(Activation_TryReadKeyIdFromOpenKey(hKey, szKeyId, cchKeyId)) {
                    RegCloseKey(hKey);
                    return;
                }
                RegCloseKey(hKey);
            }
        }
    }
}

static VOID Activation_LoadServerConfig()
{
    HKEY hKey = NULL;
    DWORD dwType = REG_NONE;
    DWORD cbData = 0;
    DWORD dwIndex = 0;
    DWORD dwHoursBack = 0;
    DWORD cchSubKey = 0;
    LONG lStatus;
    BOOL fHostLoaded = FALSE;
    BOOL fPortLoaded = FALSE;
    BOOL fUseHttpsLoaded = FALSE;
    BOOL fIgnoreCertErrorsLoaded = FALSE;
    CHAR szHostA[256] = { 0 };
    WCHAR wszHost[256] = { 0 };
    CHAR szRegPath[128] = { 0 };
    CHAR szSubKey[256] = { 0 };
    CHAR szUserActivationKey[512] = { 0 };
    DWORD dwPort = RIVER_ACTIVATION_DEFAULT_PORT;
    DWORD dwUseHttps = 0;
    DWORD dwIgnoreCertErrors = 0;
    const HKEY hRoots[1] = { HKEY_CURRENT_USER };
    INT i;

    wcscpy_s(g_wszActivationHost, _countof(g_wszActivationHost), RIVER_ACTIVATION_DEFAULT_HOST);
    g_wActivationPort = (INTERNET_PORT)RIVER_ACTIVATION_DEFAULT_PORT;
    g_fActivationUseHttps = TRUE;
    g_fActivationIgnoreCertErrors = FALSE;

    for(dwHoursBack = 0; dwHoursBack <= RIVER_ACTIVATION_REG_PATH_HOURS_BACK; dwHoursBack++) {
        if(!Activation_BuildRegistryPathForHoursBack(dwHoursBack, szRegPath, _countof(szRegPath))) {
            continue;
        }

        for(i = 0; i < _countof(hRoots); i++) {
            lStatus = RegOpenKeyExA(hRoots[i], szRegPath, 0, KEY_QUERY_VALUE, &hKey);
            if(lStatus != ERROR_SUCCESS) {
                continue;
            }

            if(!fHostLoaded) {
                cbData = sizeof(szHostA);
                dwType = REG_NONE;
                lStatus = RegQueryValueExA(hKey, RIVER_ACTIVATION_REG_VALUE_SERVER_HOST, NULL, &dwType, (LPBYTE)szHostA, &cbData);
                if(lStatus == ERROR_SUCCESS && (dwType == REG_SZ || dwType == REG_EXPAND_SZ) && szHostA[0]) {
                    if(MultiByteToWideChar(CP_UTF8, 0, szHostA, -1, wszHost, _countof(wszHost)) <= 0) {
                        MultiByteToWideChar(CP_ACP, 0, szHostA, -1, wszHost, _countof(wszHost));
                    }
                    if(wszHost[0]) {
                        wcscpy_s(g_wszActivationHost, _countof(g_wszActivationHost), wszHost);
                        fHostLoaded = TRUE;
                    }
                }
            }

            if(!fPortLoaded) {
                dwType = REG_NONE;
                cbData = sizeof(dwPort);
                lStatus = RegQueryValueExA(hKey, RIVER_ACTIVATION_REG_VALUE_SERVER_PORT, NULL, &dwType, (LPBYTE)&dwPort, &cbData);
                if(lStatus == ERROR_SUCCESS && dwType == REG_DWORD && dwPort > 0 && dwPort <= 65535) {
                    g_wActivationPort = (INTERNET_PORT)dwPort;
                    fPortLoaded = TRUE;
                } else {
                    CHAR szPortA[32] = { 0 };
                    CHAR* pEnd = NULL;
                    unsigned long ulPort = 0;
                    cbData = sizeof(szPortA);
                    dwType = REG_NONE;
                    lStatus = RegQueryValueExA(hKey, RIVER_ACTIVATION_REG_VALUE_SERVER_PORT, NULL, &dwType, (LPBYTE)szPortA, &cbData);
                    if(lStatus == ERROR_SUCCESS && (dwType == REG_SZ || dwType == REG_EXPAND_SZ) && szPortA[0]) {
                        ulPort = strtoul(szPortA, &pEnd, 10);
                        if(pEnd && *pEnd == '\0' && ulPort > 0 && ulPort <= 65535) {
                            g_wActivationPort = (INTERNET_PORT)ulPort;
                            fPortLoaded = TRUE;
                        }
                    }
                }
            }

            if(!fUseHttpsLoaded) {
                dwType = REG_NONE;
                cbData = sizeof(dwUseHttps);
                lStatus = RegQueryValueExA(hKey, RIVER_ACTIVATION_REG_VALUE_SERVER_USE_HTTPS, NULL, &dwType, (LPBYTE)&dwUseHttps, &cbData);
                if(lStatus == ERROR_SUCCESS && dwType == REG_DWORD) {
                    g_fActivationUseHttps = (dwUseHttps != 0);
                    fUseHttpsLoaded = TRUE;
                }
            }

            if(!fIgnoreCertErrorsLoaded) {
                dwType = REG_NONE;
                cbData = sizeof(dwIgnoreCertErrors);
                lStatus = RegQueryValueExA(hKey, RIVER_ACTIVATION_REG_VALUE_SERVER_IGNORE_CERT_ERRORS, NULL, &dwType, (LPBYTE)&dwIgnoreCertErrors, &cbData);
                if(lStatus == ERROR_SUCCESS && dwType == REG_DWORD) {
                    g_fActivationIgnoreCertErrors = (dwIgnoreCertErrors != 0);
                    fIgnoreCertErrorsLoaded = TRUE;
                }
            }

            RegCloseKey(hKey);
            hKey = NULL;
            if(fHostLoaded && fPortLoaded && fUseHttpsLoaded && fIgnoreCertErrorsLoaded) {
                break;
            }
        }

        if(fHostLoaded && fPortLoaded && fUseHttpsLoaded && fIgnoreCertErrorsLoaded) {
            break;
        }
    }

    // If running as SYSTEM, HKCU points to .DEFAULT and may miss
    // per-user settings. Scan loaded HKEY_USERS hives as fallback.
    if(!(fHostLoaded && fPortLoaded && fUseHttpsLoaded && fIgnoreCertErrorsLoaded)) {
        for(dwHoursBack = 0; dwHoursBack <= RIVER_ACTIVATION_REG_PATH_HOURS_BACK; dwHoursBack++) {
            if(!Activation_BuildRegistryPathForHoursBack(dwHoursBack, szRegPath, _countof(szRegPath))) {
                continue;
            }

            for(dwIndex = 0;; dwIndex++) {
                FILETIME ft = { 0 };
                cchSubKey = _countof(szSubKey);
                lStatus = RegEnumKeyExA(HKEY_USERS, dwIndex, szSubKey, &cchSubKey, NULL, NULL, NULL, &ft);
                if(lStatus != ERROR_SUCCESS) {
                    break;
                }
                if(
                    !_stricmp(szSubKey, ".DEFAULT") ||
                    !_stricmp(szSubKey, "S-1-5-18") ||
                    !_stricmp(szSubKey, "S-1-5-19") ||
                    !_stricmp(szSubKey, "S-1-5-20") ||
                    strstr(szSubKey, "_Classes")
                ) {
                    continue;
                }
                _snprintf_s(szUserActivationKey, _countof(szUserActivationKey), _TRUNCATE, "%s\\%s", szSubKey, szRegPath);
                lStatus = RegOpenKeyExA(HKEY_USERS, szUserActivationKey, 0, KEY_QUERY_VALUE, &hKey);
                if(lStatus != ERROR_SUCCESS) {
                    continue;
                }

                if(!fHostLoaded) {
                    cbData = sizeof(szHostA);
                    dwType = REG_NONE;
                    lStatus = RegQueryValueExA(hKey, RIVER_ACTIVATION_REG_VALUE_SERVER_HOST, NULL, &dwType, (LPBYTE)szHostA, &cbData);
                    if(lStatus == ERROR_SUCCESS && (dwType == REG_SZ || dwType == REG_EXPAND_SZ) && szHostA[0]) {
                        if(MultiByteToWideChar(CP_UTF8, 0, szHostA, -1, wszHost, _countof(wszHost)) <= 0) {
                            MultiByteToWideChar(CP_ACP, 0, szHostA, -1, wszHost, _countof(wszHost));
                        }
                        if(wszHost[0]) {
                            wcscpy_s(g_wszActivationHost, _countof(g_wszActivationHost), wszHost);
                            fHostLoaded = TRUE;
                        }
                    }
                }

                if(!fPortLoaded) {
                    dwType = REG_NONE;
                    cbData = sizeof(dwPort);
                    lStatus = RegQueryValueExA(hKey, RIVER_ACTIVATION_REG_VALUE_SERVER_PORT, NULL, &dwType, (LPBYTE)&dwPort, &cbData);
                    if(lStatus == ERROR_SUCCESS && dwType == REG_DWORD && dwPort > 0 && dwPort <= 65535) {
                        g_wActivationPort = (INTERNET_PORT)dwPort;
                        fPortLoaded = TRUE;
                    }
                }

                if(!fUseHttpsLoaded) {
                    dwType = REG_NONE;
                    cbData = sizeof(dwUseHttps);
                    lStatus = RegQueryValueExA(hKey, RIVER_ACTIVATION_REG_VALUE_SERVER_USE_HTTPS, NULL, &dwType, (LPBYTE)&dwUseHttps, &cbData);
                    if(lStatus == ERROR_SUCCESS && dwType == REG_DWORD) {
                        g_fActivationUseHttps = (dwUseHttps != 0);
                        fUseHttpsLoaded = TRUE;
                    }
                }

                if(!fIgnoreCertErrorsLoaded) {
                    dwType = REG_NONE;
                    cbData = sizeof(dwIgnoreCertErrors);
                    lStatus = RegQueryValueExA(hKey, RIVER_ACTIVATION_REG_VALUE_SERVER_IGNORE_CERT_ERRORS, NULL, &dwType, (LPBYTE)&dwIgnoreCertErrors, &cbData);
                    if(lStatus == ERROR_SUCCESS && dwType == REG_DWORD) {
                        g_fActivationIgnoreCertErrors = (dwIgnoreCertErrors != 0);
                        fIgnoreCertErrorsLoaded = TRUE;
                    }
                }

                RegCloseKey(hKey);
                hKey = NULL;
                if(fHostLoaded && fPortLoaded && fUseHttpsLoaded && fIgnoreCertErrorsLoaded) {
                    break;
                }
            }

            if(fHostLoaded && fPortLoaded && fUseHttpsLoaded && fIgnoreCertErrorsLoaded) {
                break;
            }
        }
    }

    // Fallback heuristic for existing deployments without ServerUseHttps.
    if(!fUseHttpsLoaded && g_wActivationPort == 443) {
        g_fActivationUseHttps = TRUE;
    }
}

static VOID Activation_WriteStatus(_In_ DWORD dwStatus)
{
    HKEY hKey = NULL;
    CHAR szRegPath[128] = { 0 };
    DWORD cbStatus = sizeof(dwStatus);
    LONG lStatus;

    if(!Activation_BuildRegistryPathForHoursBack(0, szRegPath, _countof(szRegPath))) {
        return;
    }

    lStatus = RegCreateKeyExA(HKEY_LOCAL_MACHINE, szRegPath, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL);
    if(lStatus == ERROR_SUCCESS) {
        RegSetValueExA(hKey, RIVER_ACTIVATION_REG_VALUE_STATUS, 0, REG_DWORD, (const BYTE*)&dwStatus, cbStatus);
        RegCloseKey(hKey);
        return;
    }

    lStatus = RegCreateKeyExA(HKEY_CURRENT_USER, szRegPath, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL);
    if(lStatus == ERROR_SUCCESS) {
        RegSetValueExA(hKey, RIVER_ACTIVATION_REG_VALUE_STATUS, 0, REG_DWORD, (const BYTE*)&dwStatus, cbStatus);
        RegCloseKey(hKey);
    }
}

static BOOL Activation_Sha256(_In_reads_(cbData) const BYTE* pbData, _In_ DWORD cbData, _Out_writes_(32) BYTE bHash[32])
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHashObject = 0, cbDataOut = 0;
    PBYTE pbHashObject = NULL;
    BOOL fResult = FALSE;
    if(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) { goto fail; }
    if(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbHashObject, sizeof(cbHashObject), &cbDataOut, 0) != 0) { goto fail; }
    pbHashObject = (PBYTE)LocalAlloc(LMEM_FIXED, cbHashObject);
    if(!pbHashObject) { goto fail; }
    if(BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0) != 0) { goto fail; }
    if(BCryptHashData(hHash, (PUCHAR)pbData, cbData, 0) != 0) { goto fail; }
    if(BCryptFinishHash(hHash, bHash, 32, 0) != 0) { goto fail; }
    fResult = TRUE;
fail:
    if(hHash) { BCryptDestroyHash(hHash); }
    if(pbHashObject) { LocalFree(pbHashObject); }
    if(hAlg) { BCryptCloseAlgorithmProvider(hAlg, 0); }
    return fResult;
}

static BOOL Activation_SignMessage(_In_reads_(cbPrivBlob) const BYTE* pbPrivBlob, _In_ DWORD cbPrivBlob, _In_z_ LPCSTR szMessage, _Out_writes_(cchSigHex) LPSTR szSigHex, _In_ DWORD cchSigHex)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BYTE bHash[32] = { 0 };
    DWORD cbSig = 0;
    DWORD cbSigOut = 0;
    PBYTE pbSig = NULL;
    BCRYPT_PKCS1_PADDING_INFO padInfo = { BCRYPT_SHA256_ALGORITHM };
    BOOL fResult = FALSE;

    szSigHex[0] = '\0';
    if(!Activation_Sha256((const BYTE*)szMessage, (DWORD)strlen(szMessage), bHash)) { goto fail; }
    if(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0) != 0) { goto fail; }
    if(BCryptImportKeyPair(hAlg, NULL, BCRYPT_RSAPRIVATE_BLOB, &hKey, (PUCHAR)pbPrivBlob, cbPrivBlob, 0) != 0) { goto fail; }
    if(BCryptSignHash(hKey, &padInfo, bHash, sizeof(bHash), NULL, 0, &cbSig, BCRYPT_PAD_PKCS1) != 0) { goto fail; }
    pbSig = (PBYTE)LocalAlloc(LMEM_FIXED, cbSig);
    if(!pbSig) { goto fail; }
    if(BCryptSignHash(hKey, &padInfo, bHash, sizeof(bHash), pbSig, cbSig, &cbSigOut, BCRYPT_PAD_PKCS1) != 0) { goto fail; }
    if(cbSigOut != cbSig) { goto fail; }
    Activation_HexEncode(pbSig, cbSigOut, szSigHex, cchSigHex);
    fResult = szSigHex[0] != '\0';
fail:
    if(pbSig) {
        SecureZeroMemory(pbSig, cbSig);
        LocalFree(pbSig);
    }
    if(hKey) { BCryptDestroyKey(hKey); }
    if(hAlg) { BCryptCloseAlgorithmProvider(hAlg, 0); }
    return fResult;
}

static BOOL Activation_HttpPostJson(
    _In_z_ LPCWSTR wszPath,
    _In_z_ LPCSTR szPayload,
    _Out_writes_(cchBody) LPSTR szBody,
    _In_ DWORD cchBody,
    _Out_ PDWORD pdwStatusCode)
{
    BOOL fResult = FALSE;
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    DWORD dwRequestFlags = g_fActivationUseHttps ? WINHTTP_FLAG_SECURE : 0;
    DWORD dwStatusCode = 0;
    DWORD cbStatusCode = sizeof(dwStatusCode);
    DWORD cbAvail = 0;
    DWORD cbRead = 0;
    DWORD cbBody = 0;

    szBody[0] = '\0';
    *pdwStatusCode = 0;

    hSession = WinHttpOpen(RIVER_ACTIVATION_USER_AGENT, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if(!hSession) { goto fail; }
    hConnect = WinHttpConnect(hSession, RIVER_ACTIVATION_HOST, RIVER_ACTIVATION_PORT, 0);
    if(!hConnect) { goto fail; }
    hRequest = WinHttpOpenRequest(hConnect, L"POST", wszPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, dwRequestFlags);
    if(!hRequest) { goto fail; }

    if(g_fActivationUseHttps && g_fActivationIgnoreCertErrors) {
        DWORD dwSecurityFlags =
            SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwSecurityFlags, sizeof(dwSecurityFlags));
    }

    WinHttpSetTimeouts(hRequest, 2500, 2500, 3000, 3000);
    if(!WinHttpSendRequest(hRequest, L"Content-Type: application/json\r\n", (DWORD)-1L, (LPVOID)szPayload, (DWORD)strlen(szPayload), (DWORD)strlen(szPayload), 0)) {
        goto fail;
    }
    if(!WinHttpReceiveResponse(hRequest, NULL)) {
        goto fail;
    }
    if(!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &cbStatusCode, WINHTTP_NO_HEADER_INDEX)) {
        goto fail;
    }
    *pdwStatusCode = dwStatusCode;

    while(WinHttpQueryDataAvailable(hRequest, &cbAvail) && cbAvail) {
        if(cbAvail > (cchBody - 1 - cbBody)) {
            cbAvail = cchBody - 1 - cbBody;
        }
        if(!cbAvail) {
            break;
        }
        if(!WinHttpReadData(hRequest, szBody + cbBody, cbAvail, &cbRead)) {
            goto fail;
        }
        if(!cbRead) {
            break;
        }
        cbBody += cbRead;
        if(cbBody >= cchBody - 1) {
            break;
        }
    }
    szBody[cbBody] = '\0';
    fResult = TRUE;
fail:
    if(hRequest) { WinHttpCloseHandle(hRequest); }
    if(hConnect) { WinHttpCloseHandle(hConnect); }
    if(hSession) { WinHttpCloseHandle(hSession); }
    return fResult;
}

_Success_(return)
static BOOL Activation_PerformOnlineValidation(_Out_ PDWORD pdwTtlSec)
{
    BOOL fResult = FALSE;
    DWORD dwStatusCode = 0;
    DWORD dwTtlSec = RIVER_ACTIVATION_DEFAULT_TTL_SEC;
    PBYTE pbPrivBlob = NULL;
    DWORD cbPrivBlob = 0;
    CHAR szMachineId[128] = { 0 };
    CHAR szChallengePayload[512] = { 0 };
    CHAR szChallengeRsp[4096] = { 0 };
    CHAR szActivatePayload[8192] = { 0 };
    CHAR szActivateRsp[4096] = { 0 };
    CHAR szChallengeId[256] = { 0 };
    CHAR szChallenge[256] = { 0 };
    CHAR szKeyId[128] = { 0 };
    CHAR szSignMessage[1024] = { 0 };
    CHAR szSignatureHex[2048] = { 0 };

    if(pdwTtlSec) {
        *pdwTtlSec = RIVER_ACTIVATION_DEFAULT_TTL_SEC;
    }

    Activation_MakeMachineId(szMachineId, _countof(szMachineId));
    Activation_LoadKeyId(szKeyId, _countof(szKeyId));

    _snprintf_s(
        szChallengePayload,
        _countof(szChallengePayload),
        _TRUNCATE,
        "{\"product\":\"%s\",\"machine\":\"%s\",\"key_id\":\"%s\"}",
        RIVER_ACTIVATION_PRODUCT,
        szMachineId,
        szKeyId
    );
    if(!Activation_HttpPostJson(RIVER_ACTIVATION_PATH_CHALLENGE, szChallengePayload, szChallengeRsp, _countof(szChallengeRsp), &dwStatusCode)) {
        goto fail;
    }
    if(dwStatusCode != 200 || !Activation_ParseBoolTrue(szChallengeRsp, "ok")) {
        goto fail;
    }
    if(!Activation_JsonGetString(szChallengeRsp, "challenge_id", szChallengeId, _countof(szChallengeId))) {
        goto fail;
    }
    if(!Activation_JsonGetString(szChallengeRsp, "challenge", szChallenge, _countof(szChallenge))) {
        goto fail;
    }

    if(!Activation_LoadPrivateKeyBlob(&pbPrivBlob, &cbPrivBlob)) {
        goto fail;
    }
    _snprintf_s(
        szSignMessage,
        _countof(szSignMessage),
        _TRUNCATE,
        "%s|%s|%s|%s|%s",
        szChallengeId,
        szChallenge,
        RIVER_ACTIVATION_PRODUCT,
        szMachineId,
        szKeyId
    );
    if(!Activation_SignMessage(pbPrivBlob, cbPrivBlob, szSignMessage, szSignatureHex, _countof(szSignatureHex))) {
        goto fail;
    }

    _snprintf_s(
        szActivatePayload,
        _countof(szActivatePayload),
        _TRUNCATE,
        "{\"product\":\"%s\",\"machine\":\"%s\",\"key_id\":\"%s\",\"challenge_id\":\"%s\",\"challenge\":\"%s\",\"signature\":\"%s\"}",
        RIVER_ACTIVATION_PRODUCT,
        szMachineId,
        szKeyId,
        szChallengeId,
        szChallenge,
        szSignatureHex
    );
    if(!Activation_HttpPostJson(RIVER_ACTIVATION_PATH_ACTIVATE, szActivatePayload, szActivateRsp, _countof(szActivateRsp), &dwStatusCode)) {
        goto fail;
    }
    if(dwStatusCode != 200 || !Activation_ParseBoolTrue(szActivateRsp, "ok")) {
        goto fail;
    }
    dwTtlSec = Activation_ParseTtlSec(szActivateRsp);
    if(pdwTtlSec) {
        *pdwTtlSec = dwTtlSec;
    }
    fResult = TRUE;

fail:
    if(pbPrivBlob) {
        SecureZeroMemory(pbPrivBlob, cbPrivBlob);
        LocalFree(pbPrivBlob);
    }
    return fResult;
}

static VOID Activation_UpdateAuthState(_In_ BOOL fAuthorized, _In_ DWORD dwTtlSec)
{
    ULONGLONG qwNow = GetTickCount64();
    EnterCriticalSection(&g_RiverActivationState.Lock);
    g_RiverActivationState.fInitialized = TRUE;
    g_RiverActivationState.fAuthorized = fAuthorized;
    g_RiverActivationState.qwLastAttemptTickMs = qwNow;
    if(fAuthorized) {
        g_RiverActivationState.qwExpireTickMs = qwNow + ((ULONGLONG)dwTtlSec * 1000ULL);
    } else {
        g_RiverActivationState.qwExpireTickMs = 0;
    }
    LeaveCriticalSection(&g_RiverActivationState.Lock);
    Activation_WriteStatus(fAuthorized ? RIVER_ACTIVATION_STATUS_AUTHORIZED : RIVER_ACTIVATION_STATUS_DENIED);
}

static BOOL Activation_RefreshInternal(_In_ BOOL fForce)
{
    BOOL fAuthorized;
    DWORD dwTtlSec = RIVER_ACTIVATION_DEFAULT_TTL_SEC;
    ULONGLONG qwNow = GetTickCount64();

    EnterCriticalSection(&g_RiverActivationState.Lock);
    if(!fForce && g_RiverActivationState.qwLastAttemptTickMs &&
        (qwNow - g_RiverActivationState.qwLastAttemptTickMs < RIVER_ACTIVATION_RETRY_INTERVAL_MS)) {
        fAuthorized = g_RiverActivationState.fAuthorized && (g_RiverActivationState.qwExpireTickMs > qwNow);
        LeaveCriticalSection(&g_RiverActivationState.Lock);
        return fAuthorized;
    }
    g_RiverActivationState.qwLastAttemptTickMs = qwNow;
    LeaveCriticalSection(&g_RiverActivationState.Lock);

    fAuthorized = Activation_PerformOnlineValidation(&dwTtlSec);
    Activation_UpdateAuthState(fAuthorized, dwTtlSec);
    return fAuthorized;
}

_Success_(return)
BOOL Activation_Initialize()
{
#if RIVER_ACTIVATION_BYPASS
    Activation_LoadServerConfig();
    Activation_ForceAuthorizedState(RIVER_ACTIVATION_MAX_TTL_SEC);
    return TRUE;
#else
    if(!g_RiverActivationState.fLockInitialized) {
        InitializeCriticalSection(&g_RiverActivationState.Lock);
        g_RiverActivationState.fLockInitialized = TRUE;
    }

    // Load activation server configuration from registry and mark
    // status as pending before the first online validation.
    Activation_LoadServerConfig();
    Activation_WriteStatus(RIVER_ACTIVATION_STATUS_PENDING);

    return Activation_RefreshInternal(TRUE);
#endif
}

_Success_(return)
BOOL Activation_IsAuthorized()
{
#if RIVER_ACTIVATION_BYPASS
    Activation_ForceAuthorizedState(RIVER_ACTIVATION_MAX_TTL_SEC);
    return TRUE;
#else
    BOOL fAuthorized = FALSE;
    BOOL fNeedRefresh = FALSE;
    ULONGLONG qwNow = GetTickCount64();

    if(!g_RiverActivationState.fLockInitialized) {
        return FALSE;
    }

    EnterCriticalSection(&g_RiverActivationState.Lock);
    if(!g_RiverActivationState.fInitialized) {
        fNeedRefresh = TRUE;
    } else if(!g_RiverActivationState.fAuthorized) {
        fNeedRefresh = TRUE;
    } else if(g_RiverActivationState.qwExpireTickMs <= qwNow) {
        fNeedRefresh = TRUE;
    } else if(g_RiverActivationState.qwExpireTickMs - qwNow < 60000) {
        fNeedRefresh = TRUE;
    } else {
        fAuthorized = TRUE;
    }
    LeaveCriticalSection(&g_RiverActivationState.Lock);

    if(fNeedRefresh) {
        fAuthorized = Activation_RefreshInternal(FALSE);
    }
    return fAuthorized;
#endif
}

VOID Activation_Shutdown()
{
#if RIVER_ACTIVATION_BYPASS
    if(g_RiverActivationState.fLockInitialized) {
        DeleteCriticalSection(&g_RiverActivationState.Lock);
    }
    ZeroMemory(&g_RiverActivationState, sizeof(g_RiverActivationState));
    return;
#else
    if(!g_RiverActivationState.fLockInitialized) {
        return;
    }
    EnterCriticalSection(&g_RiverActivationState.Lock);
    g_RiverActivationState.fInitialized = FALSE;
    g_RiverActivationState.fAuthorized = FALSE;
    g_RiverActivationState.qwExpireTickMs = 0;
    g_RiverActivationState.qwLastAttemptTickMs = 0;
    LeaveCriticalSection(&g_RiverActivationState.Lock);
    DeleteCriticalSection(&g_RiverActivationState.Lock);
    ZeroMemory(&g_RiverActivationState, sizeof(g_RiverActivationState));
#endif
}
