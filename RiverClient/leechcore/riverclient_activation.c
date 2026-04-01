#include "riverclient_activation.h"
#include "util.h"

#ifdef _WIN32
#include <bcrypt.h>
#include <strsafe.h>
#include <winhttp.h>
#include <winreg.h>

#pragma comment(lib, "bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define RC_REG_RIVERCLIENT "Software\\RiverClient"
#define RC_REG_ACTIVATION "Software\\RiverServer\\Activation"
#define RC_REG_MACHINE_CRYPTO "SOFTWARE\\Microsoft\\Cryptography"

typedef struct tdRC_ACTIVATION_CFG
{
    CHAR szApiBase[512];
    CHAR szLoginJwt[8192];
    CHAR szLoginSessionId[128];
    BYTE pbPrivateBlob[4096];
    DWORD cbPrivateBlob;
    DWORD dwIgnoreCertErrors;
    CHAR szMachineId[256];
} RC_ACTIVATION_CFG, *PRC_ACTIVATION_CFG;

typedef struct tdRC_HTTP_ENDPOINT
{
    WCHAR wszHost[260];
    INTERNET_PORT uPort;
    BOOL fHttps;
} RC_HTTP_ENDPOINT, *PRC_HTTP_ENDPOINT;

static VOID RcBinToHexLower(_In_reads_bytes_(cbIn) PBYTE pbIn, _In_ DWORD cbIn, _Out_writes_(cchOut) LPSTR szOut, _In_ DWORD cchOut);
static _Success_(return) BOOL RcSha256(_In_reads_bytes_(cbData) PBYTE pbData, _In_ DWORD cbData, _Out_writes_bytes_(32) PBYTE pbHash32);

static _Success_(return) BOOL RcRegReadStringA(_In_ HKEY hRoot, _In_z_ LPCSTR szSubKey, _In_z_ LPCSTR szValue, _Out_writes_(cchOut) LPSTR szOut, _In_ DWORD cchOut)
{
    HKEY hKey = NULL;
    DWORD cb = cchOut;
    LSTATUS st;
    szOut[0] = 0;
    st = RegOpenKeyExA(hRoot, szSubKey, 0, KEY_READ, &hKey);
    if(st != ERROR_SUCCESS) { return FALSE; }
    st = RegGetValueA(hKey, NULL, szValue, RRF_RT_REG_SZ, NULL, szOut, &cb);
    RegCloseKey(hKey);
    return (st == ERROR_SUCCESS) && szOut[0];
}

static _Success_(return) BOOL RcRegReadDword(_In_ HKEY hRoot, _In_z_ LPCSTR szSubKey, _In_z_ LPCSTR szValue, _Out_ PDWORD pdwValue)
{
    HKEY hKey = NULL;
    DWORD cb = sizeof(DWORD);
    LSTATUS st;
    *pdwValue = 0;
    st = RegOpenKeyExA(hRoot, szSubKey, 0, KEY_READ, &hKey);
    if(st != ERROR_SUCCESS) { return FALSE; }
    st = RegGetValueA(hKey, NULL, szValue, RRF_RT_REG_DWORD, NULL, pdwValue, &cb);
    RegCloseKey(hKey);
    return (st == ERROR_SUCCESS);
}

static _Success_(return) BOOL RcRegReadBinary(_In_ HKEY hRoot, _In_z_ LPCSTR szSubKey, _In_z_ LPCSTR szValue, _Out_writes_bytes_(cbOut) PBYTE pbOut, _In_ DWORD cbOut, _Out_ PDWORD pcbRead)
{
    HKEY hKey = NULL;
    DWORD cb = cbOut;
    LSTATUS st;
    *pcbRead = 0;
    st = RegOpenKeyExA(hRoot, szSubKey, 0, KEY_READ, &hKey);
    if(st != ERROR_SUCCESS) { return FALSE; }
    st = RegGetValueA(hKey, NULL, szValue, RRF_RT_REG_BINARY, NULL, pbOut, &cb);
    RegCloseKey(hKey);
    if(st != ERROR_SUCCESS || !cb) { return FALSE; }
    *pcbRead = cb;
    return TRUE;
}

static _Success_(return) BOOL RcAppendPart(_Inout_updates_(cchBuf) LPSTR szBuf, _In_ DWORD cchBuf, _In_z_ LPCSTR szPart)
{
    size_t cchCurrent;
    HRESULT hr;
    if(!szPart || !szPart[0]) { return TRUE; }
    cchCurrent = strnlen_s(szBuf, cchBuf);
    if(cchCurrent && (cchCurrent + 1 >= cchBuf)) { return FALSE; }
    hr = StringCchCatA(szBuf, cchBuf, cchCurrent ? "|" : "");
    if(FAILED(hr)) { return FALSE; }
    hr = StringCchCatA(szBuf, cchBuf, szPart);
    return SUCCEEDED(hr);
}

static VOID RcGetMachineId(_Out_writes_(cchOut) LPSTR szOut, _In_ DWORD cchOut)
{
    CHAR szJoined[1024] = { 0 };
    CHAR szMachineGuid[256] = { 0 };
    CHAR szComputerName[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
    CHAR szWindowsDir[MAX_PATH] = { 0 };
    CHAR szSystemDrive[MAX_PATH] = { 0 };
    BYTE pbHash[32] = { 0 };
    DWORD cchComputerName = _countof(szComputerName);
    DWORD cchSystemDrive = GetEnvironmentVariableA("SystemDrive", szSystemDrive, _countof(szSystemDrive));

    szOut[0] = 0;

    RcRegReadStringA(HKEY_LOCAL_MACHINE, RC_REG_MACHINE_CRYPTO, "MachineGuid", szMachineGuid, _countof(szMachineGuid));
    if(!GetComputerNameA(szComputerName, &cchComputerName)) {
        szComputerName[0] = 0;
    }
    if(!GetWindowsDirectoryA(szWindowsDir, _countof(szWindowsDir))) {
        szWindowsDir[0] = 0;
    }
    if(!cchSystemDrive || (cchSystemDrive >= _countof(szSystemDrive))) {
        szSystemDrive[0] = 0;
    }

    if(!RcAppendPart(szJoined, _countof(szJoined), szMachineGuid) ||
       !RcAppendPart(szJoined, _countof(szJoined), szComputerName) ||
       !RcAppendPart(szJoined, _countof(szJoined), szWindowsDir) ||
       !RcAppendPart(szJoined, _countof(szJoined), szSystemDrive)) {
        szJoined[0] = 0;
    }

    if(!szJoined[0]) {
        _snprintf_s(szJoined, _countof(szJoined), _TRUNCATE, "%s|fallback", szComputerName[0] ? szComputerName : "UNKNOWN_MACHINE");
    }

    if(!RcSha256((PBYTE)szJoined, (DWORD)strlen(szJoined), pbHash)) {
        strncpy_s(szOut, cchOut, szComputerName[0] ? szComputerName : "UNKNOWN_MACHINE", _TRUNCATE);
        return;
    }

    RcBinToHexLower(pbHash, sizeof(pbHash), szOut, cchOut);
}

static _Success_(return) BOOL RcLoadConfig(_Out_ PRC_ACTIVATION_CFG pCfg)
{
    ZeroMemory(pCfg, sizeof(RC_ACTIVATION_CFG));
    if(!RcRegReadStringA(HKEY_CURRENT_USER, RC_REG_RIVERCLIENT, "ActivationApiBase", pCfg->szApiBase, _countof(pCfg->szApiBase))) {
        if(!RcRegReadStringA(HKEY_LOCAL_MACHINE, RC_REG_RIVERCLIENT, "ActivationApiBase", pCfg->szApiBase, _countof(pCfg->szApiBase))) {
            return FALSE;
        }
    }
    if(!RcRegReadStringA(HKEY_CURRENT_USER, RC_REG_RIVERCLIENT, "LoginJwt", pCfg->szLoginJwt, _countof(pCfg->szLoginJwt))) {
        if(!RcRegReadStringA(HKEY_LOCAL_MACHINE, RC_REG_RIVERCLIENT, "LoginJwt", pCfg->szLoginJwt, _countof(pCfg->szLoginJwt))) {
            return FALSE;
        }
    }
    if(!RcRegReadStringA(HKEY_CURRENT_USER, RC_REG_RIVERCLIENT, "LoginSessionId", pCfg->szLoginSessionId, _countof(pCfg->szLoginSessionId))) {
        if(!RcRegReadStringA(HKEY_LOCAL_MACHINE, RC_REG_RIVERCLIENT, "LoginSessionId", pCfg->szLoginSessionId, _countof(pCfg->szLoginSessionId))) {
            return FALSE;
        }
    }
    if(!RcRegReadBinary(HKEY_CURRENT_USER, RC_REG_ACTIVATION, "PrivateKeyBlob", pCfg->pbPrivateBlob, sizeof(pCfg->pbPrivateBlob), &pCfg->cbPrivateBlob)) {
        if(!RcRegReadBinary(HKEY_LOCAL_MACHINE, RC_REG_ACTIVATION, "PrivateKeyBlob", pCfg->pbPrivateBlob, sizeof(pCfg->pbPrivateBlob), &pCfg->cbPrivateBlob)) {
            return FALSE;
        }
    }
    if(!RcRegReadDword(HKEY_CURRENT_USER, RC_REG_ACTIVATION, "ServerIgnoreCertErrors", &pCfg->dwIgnoreCertErrors)) {
        RcRegReadDword(HKEY_LOCAL_MACHINE, RC_REG_ACTIVATION, "ServerIgnoreCertErrors", &pCfg->dwIgnoreCertErrors);
    }
    RcGetMachineId(pCfg->szMachineId, _countof(pCfg->szMachineId));
    return TRUE;
}

static _Success_(return) BOOL RcParseBaseUrl(_In_z_ LPCSTR szBaseUrl, _Out_ PRC_HTTP_ENDPOINT pEp)
{
    WCHAR wszUrl[1024] = { 0 };
    WCHAR wszHost[260] = { 0 };
    URL_COMPONENTS uc = { 0 };
    int cch;
    ZeroMemory(pEp, sizeof(RC_HTTP_ENDPOINT));

    cch = MultiByteToWideChar(CP_UTF8, 0, szBaseUrl, -1, wszUrl, _countof(wszUrl));
    if(!cch) { return FALSE; }

    uc.dwStructSize = sizeof(uc);
    uc.lpszHostName = wszHost;
    uc.dwHostNameLength = _countof(wszHost);
    if(!WinHttpCrackUrl(wszUrl, 0, 0, &uc)) { return FALSE; }
    if(!wszHost[0]) { return FALSE; }

    pEp->fHttps = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    pEp->uPort = uc.nPort ? uc.nPort : (pEp->fHttps ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT);
    wcsncpy_s(pEp->wszHost, _countof(pEp->wszHost), wszHost, _TRUNCATE);
    return TRUE;
}

static _Success_(return) BOOL RcReadAllResponse(_In_ HINTERNET hRequest, _Out_ PBYTE *ppbOut, _Out_ PDWORD pcbOut)
{
    DWORD cbTotal = 0, cbAlloc = 0x4000, cbChunk = 0;
    PBYTE pb = (PBYTE)LocalAlloc(LMEM_FIXED, cbAlloc + 1);
    if(!pb) { return FALSE; }
    while(WinHttpReadData(hRequest, pb + cbTotal, cbAlloc - cbTotal, &cbChunk) && cbChunk) {
        cbTotal += cbChunk;
        if(cbTotal + 0x1000 > cbAlloc) {
            PBYTE pb2 = (PBYTE)LocalAlloc(LMEM_FIXED, cbAlloc * 2 + 1);
            if(!pb2) {
                LocalFree(pb);
                return FALSE;
            }
            memcpy(pb2, pb, cbTotal);
            LocalFree(pb);
            pb = pb2;
            cbAlloc *= 2;
        }
    }
    pb[cbTotal] = 0;
    *ppbOut = pb;
    *pcbOut = cbTotal;
    return TRUE;
}

static _Success_(return) BOOL RcHttpPostJson(
    _In_ PRC_HTTP_ENDPOINT pEp,
    _In_z_ LPCWSTR wszPath,
    _In_z_ LPCSTR szBearerJwt,
    _In_z_ LPCSTR szJsonBody,
    _In_ DWORD dwIgnoreCertErrors,
    _Out_ PBYTE *ppbResp,
    _Out_ PDWORD pcbResp,
    _Out_ PDWORD pdwStatus)
{
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    WCHAR wszHeaders[9000] = { 0 };
    DWORD dwHeaderLen = 0, dwBodyLen = (DWORD)strlen(szJsonBody), dwStatus = 0, dwStatusSize = sizeof(dwStatus);
    BOOL fOk = FALSE;
    *ppbResp = NULL;
    *pcbResp = 0;
    *pdwStatus = 0;

    hSession = WinHttpOpen(L"riverclient-activation/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if(!hSession) { goto cleanup; }
    WinHttpSetTimeouts(hSession, 3000, 3000, 20000, 20000);
    hConnect = WinHttpConnect(hSession, pEp->wszHost, pEp->uPort, 0);
    if(!hConnect) { goto cleanup; }
    hRequest = WinHttpOpenRequest(
        hConnect,
        L"POST",
        wszPath,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        pEp->fHttps ? WINHTTP_FLAG_SECURE : 0);
    if(!hRequest) { goto cleanup; }

    if(pEp->fHttps && dwIgnoreCertErrors) {
        DWORD dwSecFlags =
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
            SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwSecFlags, sizeof(dwSecFlags));
    }

    _snwprintf_s(
        wszHeaders,
        _countof(wszHeaders),
        _TRUNCATE,
        L"Content-Type: application/json\r\nAccept: application/json\r\nAuthorization: Bearer %hs\r\nConnection: close\r\n",
        szBearerJwt);
    dwHeaderLen = (DWORD)-1;

    if(!WinHttpSendRequest(
        hRequest,
        wszHeaders,
        dwHeaderLen,
        (LPVOID)szJsonBody,
        dwBodyLen,
        dwBodyLen,
        0)) { goto cleanup; }

    if(!WinHttpReceiveResponse(hRequest, NULL)) { goto cleanup; }
    if(!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &dwStatus, &dwStatusSize, WINHTTP_NO_HEADER_INDEX)) {
        goto cleanup;
    }
    *pdwStatus = dwStatus;
    if(!RcReadAllResponse(hRequest, ppbResp, pcbResp)) { goto cleanup; }
    fOk = TRUE;

cleanup:
    if(hRequest) { WinHttpCloseHandle(hRequest); }
    if(hConnect) { WinHttpCloseHandle(hConnect); }
    if(hSession) { WinHttpCloseHandle(hSession); }
    return fOk;
}

static const CHAR* RcJsonFindKey(_In_z_ LPCSTR szJson, _In_z_ LPCSTR szKey)
{
    CHAR szPat[96] = { 0 };
    LPCSTR p;
    _snprintf_s(szPat, _countof(szPat), _TRUNCATE, "\"%s\"", szKey);
    p = strstr(szJson, szPat);
    if(!p) { return NULL; }
    p += strlen(szPat);
    while(*p && ((*p == ' ') || (*p == '\t') || (*p == '\r') || (*p == '\n'))) { p++; }
    if(*p != ':') { return NULL; }
    p++;
    while(*p && ((*p == ' ') || (*p == '\t') || (*p == '\r') || (*p == '\n'))) { p++; }
    return p;
}

static _Success_(return) BOOL RcJsonGetBool(_In_z_ LPCSTR szJson, _In_z_ LPCSTR szKey, _Out_ PBOOL pfValue)
{
    LPCSTR p = RcJsonFindKey(szJson, szKey);
    if(!p) { return FALSE; }
    if(0 == _strnicmp(p, "true", 4)) { *pfValue = TRUE; return TRUE; }
    if(0 == _strnicmp(p, "false", 5)) { *pfValue = FALSE; return TRUE; }
    return FALSE;
}

static _Success_(return) BOOL RcJsonGetString(_In_z_ LPCSTR szJson, _In_z_ LPCSTR szKey, _Out_writes_(cchOut) LPSTR szOut, _In_ DWORD cchOut)
{
    LPCSTR p = RcJsonFindKey(szJson, szKey);
    DWORD i = 0;
    szOut[0] = 0;
    if(!p || (*p != '"')) { return FALSE; }
    p++;
    while(*p && (*p != '"') && (i + 1 < cchOut)) {
        if(*p == '\\' && p[1]) { p++; }
        szOut[i++] = *p++;
    }
    szOut[i] = 0;
    return (*p == '"') && (i > 0);
}

static VOID RcBinToHexLower(_In_reads_bytes_(cbIn) PBYTE pbIn, _In_ DWORD cbIn, _Out_writes_(cchOut) LPSTR szOut, _In_ DWORD cchOut)
{
    static const CHAR* hex = "0123456789abcdef";
    DWORD i;
    if(cchOut < (cbIn * 2 + 1)) {
        szOut[0] = 0;
        return;
    }
    for(i = 0; i < cbIn; i++) {
        szOut[2 * i] = hex[pbIn[i] >> 4];
        szOut[2 * i + 1] = hex[pbIn[i] & 0x0f];
    }
    szOut[cbIn * 2] = 0;
}

static _Success_(return) BOOL RcSha256(_In_reads_bytes_(cbData) PBYTE pbData, _In_ DWORD cbData, _Out_writes_bytes_(32) PBYTE pbHash32)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PUCHAR pbObj = NULL;
    DWORD cbObj = 0, cbRes = 0;
    NTSTATUS st;
    BOOL fOk = FALSE;
    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if(!NT_SUCCESS(st)) { goto cleanup; }
    st = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbObj, sizeof(cbObj), &cbRes, 0);
    if(!NT_SUCCESS(st) || !cbObj) { goto cleanup; }
    pbObj = (PUCHAR)LocalAlloc(0, cbObj);
    if(!pbObj) { goto cleanup; }
    st = BCryptCreateHash(hAlg, &hHash, pbObj, cbObj, NULL, 0, 0);
    if(!NT_SUCCESS(st)) { goto cleanup; }
    st = BCryptHashData(hHash, pbData, cbData, 0);
    if(!NT_SUCCESS(st)) { goto cleanup; }
    st = BCryptFinishHash(hHash, pbHash32, 32, 0);
    if(!NT_SUCCESS(st)) { goto cleanup; }
    fOk = TRUE;
cleanup:
    if(hHash) { BCryptDestroyHash(hHash); }
    if(hAlg) { BCryptCloseAlgorithmProvider(hAlg, 0); }
    if(pbObj) { LocalFree(pbObj); }
    return fOk;
}

static _Success_(return) BOOL RcSignMessagePkcs1Sha256Hex(
    _In_reads_bytes_(cbPrivateBlob) PBYTE pbPrivateBlob,
    _In_ DWORD cbPrivateBlob,
    _In_z_ LPCSTR szMessage,
    _Out_writes_(cchSigHex) LPSTR szSigHex,
    _In_ DWORD cchSigHex)
{
    BCRYPT_ALG_HANDLE hRsa = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BYTE pbHash[32] = { 0 };
    BYTE* pbSig = NULL;
    DWORD cbSig = 0, cbRes = 0;
    BCRYPT_PKCS1_PADDING_INFO padInfo = { BCRYPT_SHA256_ALGORITHM };
    NTSTATUS st;
    BOOL fOk = FALSE;

    if(!RcSha256((PBYTE)szMessage, (DWORD)strlen(szMessage), pbHash)) { return FALSE; }
    st = BCryptOpenAlgorithmProvider(&hRsa, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if(!NT_SUCCESS(st)) { goto cleanup; }
    st = BCryptImportKeyPair(hRsa, NULL, BCRYPT_RSAPRIVATE_BLOB, &hKey, pbPrivateBlob, cbPrivateBlob, 0);
    if(!NT_SUCCESS(st)) { goto cleanup; }
    st = BCryptSignHash(hKey, &padInfo, pbHash, sizeof(pbHash), NULL, 0, &cbSig, BCRYPT_PAD_PKCS1);
    if(!NT_SUCCESS(st) || !cbSig) { goto cleanup; }
    pbSig = (PBYTE)LocalAlloc(0, cbSig);
    if(!pbSig) { goto cleanup; }
    st = BCryptSignHash(hKey, &padInfo, pbHash, sizeof(pbHash), pbSig, cbSig, &cbRes, BCRYPT_PAD_PKCS1);
    if(!NT_SUCCESS(st) || cbRes != cbSig) { goto cleanup; }
    RcBinToHexLower(pbSig, cbSig, szSigHex, cchSigHex);
    fOk = (szSigHex[0] != 0);
cleanup:
    if(pbSig) { LocalFree(pbSig); }
    if(hKey) { BCryptDestroyKey(hKey); }
    if(hRsa) { BCryptCloseAlgorithmProvider(hRsa, 0); }
    return fOk;
}

_Success_(return)
BOOL RcActivation_EnsureActivated(_Inout_ PLC_CONTEXT ctxLC)
{
    RC_ACTIVATION_CFG cfg;
    RC_HTTP_ENDPOINT ep;
    BYTE bNonce[8] = { 0 };
    CHAR szNonce[2 * sizeof(bNonce) + 1] = { 0 };
    CHAR szBody[2048] = { 0 };
    PBYTE pbResp = NULL;
    DWORD cbResp = 0, dwStatus = 0;
    BOOL fOk = FALSE, fApiOk = FALSE;
    CHAR szChallengeId[128] = { 0 };
    CHAR szChallenge[256] = { 0 };
    CHAR szKeyId[128] = { 0 };
    CHAR szReason[256] = { 0 };
    CHAR szSignMsg[1024] = { 0 };
    CHAR szSigHex[1200] = { 0 };

    if(!RcLoadConfig(&cfg)) {
        lcprintf(ctxLC, "RIVERCLIENT_ACT: missing activation config/login context in registry.\n");
        return FALSE;
    }
    if(!RcParseBaseUrl(cfg.szApiBase, &ep)) {
        lcprintf(ctxLC, "RIVERCLIENT_ACT: invalid ActivationApiBase='%s'.\n", cfg.szApiBase);
        return FALSE;
    }

    Util_GenRandom(bNonce, sizeof(bNonce));
    RcBinToHexLower(bNonce, sizeof(bNonce), szNonce, sizeof(szNonce));

    _snprintf_s(
        szBody,
        _countof(szBody),
        _TRUNCATE,
        "{\"machineId\":\"%s\",\"clientNonce\":\"%s\",\"clientVersion\":\"riverclient\"}",
        cfg.szMachineId,
        szNonce);

    if(!RcHttpPostJson(&ep, L"/api/riverclient/challenge", cfg.szLoginJwt, szBody, cfg.dwIgnoreCertErrors, &pbResp, &cbResp, &dwStatus)) {
        lcprintf(ctxLC, "RIVERCLIENT_ACT: challenge request failed.\n");
        return FALSE;
    }
    if(dwStatus != 200) {
        lcprintf(ctxLC, "RIVERCLIENT_ACT: challenge HTTP status=%u.\n", dwStatus);
        goto cleanup;
    }
    if(!RcJsonGetBool((LPCSTR)pbResp, "ok", &fApiOk) || !fApiOk) {
        RcJsonGetString((LPCSTR)pbResp, "reason", szReason, _countof(szReason));
        lcprintf(ctxLC, "RIVERCLIENT_ACT: challenge rejected reason='%s'.\n", szReason[0] ? szReason : "unknown");
        goto cleanup;
    }
    if(!RcJsonGetString((LPCSTR)pbResp, "challengeId", szChallengeId, _countof(szChallengeId)) ||
       !RcJsonGetString((LPCSTR)pbResp, "challenge", szChallenge, _countof(szChallenge)) ||
       !RcJsonGetString((LPCSTR)pbResp, "keyId", szKeyId, _countof(szKeyId))) {
        lcprintf(ctxLC, "RIVERCLIENT_ACT: invalid challenge response payload.\n");
        goto cleanup;
    }
    LocalFree(pbResp);
    pbResp = NULL;
    cbResp = 0;

    _snprintf_s(
        szSignMsg,
        _countof(szSignMsg),
        _TRUNCATE,
        "%s|%s|RiverClient|%s|%s|%s",
        szChallengeId,
        szChallenge,
        cfg.szMachineId,
        szKeyId,
        cfg.szLoginSessionId);

    if(!RcSignMessagePkcs1Sha256Hex(cfg.pbPrivateBlob, cfg.cbPrivateBlob, szSignMsg, szSigHex, _countof(szSigHex))) {
        lcprintf(ctxLC, "RIVERCLIENT_ACT: signature generation failed.\n");
        goto cleanup;
    }

    _snprintf_s(
        szBody,
        _countof(szBody),
        _TRUNCATE,
        "{\"machineId\":\"%s\",\"challengeId\":\"%s\",\"signature\":\"%s\"}",
        cfg.szMachineId,
        szChallengeId,
        szSigHex);

    if(!RcHttpPostJson(&ep, L"/api/riverclient/activate", cfg.szLoginJwt, szBody, cfg.dwIgnoreCertErrors, &pbResp, &cbResp, &dwStatus)) {
        lcprintf(ctxLC, "RIVERCLIENT_ACT: activate request failed.\n");
        goto cleanup;
    }
    if(dwStatus != 200) {
        lcprintf(ctxLC, "RIVERCLIENT_ACT: activate HTTP status=%u.\n", dwStatus);
        goto cleanup;
    }
    if(!RcJsonGetBool((LPCSTR)pbResp, "ok", &fApiOk) || !fApiOk) {
        RcJsonGetString((LPCSTR)pbResp, "reason", szReason, _countof(szReason));
        lcprintf(ctxLC, "RIVERCLIENT_ACT: activate rejected reason='%s'.\n", szReason[0] ? szReason : "unknown");
        goto cleanup;
    }

    fOk = TRUE;
    lcprintf(ctxLC, "RIVERCLIENT_ACT: activation OK. machine=%s\n", cfg.szMachineId);

cleanup:
    if(pbResp) { LocalFree(pbResp); }
    return fOk;
}
#endif /* _WIN32 */
