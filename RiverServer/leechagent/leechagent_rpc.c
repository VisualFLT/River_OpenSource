// leechsvc_rpc.c : implementation of RPC related functionality.
//
// (c) Ulf Frisk, 2018-2026
// Author: Ulf Frisk, pcileech@frizk.net
//
#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#include "leechagent.h"
#include "leechagent_rpc.h"
#if LEECHRPC_ENABLE_NATIVE_RPC
#include "leechrpc_h.h"
#endif
#include "leechrpc.h"
#include <stdio.h>
#define SECURITY_WIN32
#include <security.h>
#include <sddl.h>
#include <leechgrpc.h>
#include "leechagent_logging.h"

PBYTE LeechRpc_ServerResponseAlloc(_In_ DWORD cb);
PBYTE LeechRpc_ServerResponseAllocFrameReady(_In_ DWORD cb);
VOID LeechRpc_ServerResponseFree(_Pre_maybenull_ PBYTE pb);
BOOL LeechRpc_ServerResponseGetFrameBuffer(_In_ PBYTE pb, _In_ DWORD cbPlain, _Out_ PBYTE *ppbFrame, _Out_ DWORD *pcbFrame);

// MS-RPC:
#if LEECHRPC_ENABLE_NATIVE_RPC
RPC_BINDING_VECTOR *g_rpc_pbindingVector = NULL;
#endif

// gRPC:
HANDLE g_hGRPC = NULL;
pfn_leechgrpc_server_create_insecure g_pfn_leechgrpc_server_create_insecure;
pfn_leechgrpc_server_create_secure_p12 g_pfn_leechgrpc_server_create_secure_p12;
pfn_leechgrpc_server_shutdown g_pfn_leechgrpc_server_shutdown;
VOID LeechGRPC_ReservedSubmitCommand(_In_opt_ PVOID ctx, _In_ PBYTE pbIn, _In_ SIZE_T cbIn, _Out_ PBYTE *ppbOut, _Out_ SIZE_T *pcbOut);

VOID LeechSvcRpc_WriteInfoEventLog(_In_z_ _Printf_format_string_ char const* const _Format, ...)
{
    CHAR szBuffer[0x1000] = { 0 };
    va_list argptr;
    HANDLE hEventInfoLog;
    DWORD dwSize;
    LPSTR szArgs[2] = { "River:", "" };
    va_start(argptr, _Format);
    dwSize = (DWORD)vsnprintf(szBuffer, 0x1000 - 1, _Format, argptr);
    va_end(argptr);
    if(!dwSize) { return; }
    hEventInfoLog = RegisterEventSourceA(NULL, "River");
    if(!hEventInfoLog) { return; }
    szArgs[1] = szBuffer;
    ReportEventA(
        hEventInfoLog,
        EVENTLOG_INFORMATION_TYPE,
        0,
        42666,
        NULL,
        2,
        0,
        (LPCSTR*)&szArgs,
        NULL
    );
    printf("%s", szBuffer);
    DeregisterEventSource(hEventInfoLog);
}

/*
* In a NTLM authentication scenario CheckTokenMembership() may fail.
* Perform a secondary check to see if the user is a member of the local administrators group.
* -- hImpersonationToken: The impersonation token of the connecting user.
* -- return: TRUE if the user is a member of the local administrators group, FALSE otherwise.
*/
BOOL LeechSvcRpc_SecurityCallback_IsAdminNtlm(_In_ HANDLE hImpersonationToken)
{
    BOOL fResult = FALSE;
    DWORD i, cbTokenInfoLength = 0;
    PTOKEN_GROUPS pTokenGroups = NULL;
    LPWSTR wszSID = NULL;
    if(!GetTokenInformation(hImpersonationToken, TokenGroups, NULL, 0, &cbTokenInfoLength) && (GetLastError() != ERROR_INSUFFICIENT_BUFFER)) { goto fail; }
    if(!(pTokenGroups = (PTOKEN_GROUPS)LocalAlloc(LMEM_ZEROINIT, cbTokenInfoLength))) { goto fail; }
    if(!GetTokenInformation(hImpersonationToken, TokenGroups, pTokenGroups, cbTokenInfoLength, &cbTokenInfoLength)) { goto fail; }
    for(i = 0; i < pTokenGroups->GroupCount; i++) {
        if(!ConvertSidToStringSidW(pTokenGroups->Groups[i].Sid, &wszSID) || !wszSID) {
            continue;
        }
        if(!wcscmp(wszSID, L"S-1-5-32-544")) {
            fResult = TRUE;
            break;
        }
        LocalFree(wszSID); wszSID = NULL;
    }
fail:
    LocalFree(pTokenGroups);
    LocalFree(wszSID);
    return fResult;
}

/*
* RPC callback function to authorize the connecting user. The user is will be
* authorized if it's a member of the Local 'Administrators' group.
* NB! if user is connecting locally - the user must be an elevated admin.
*/
#if LEECHRPC_ENABLE_NATIVE_RPC
RPC_STATUS CALLBACK LeechSvcRpc_SecurityCallback(RPC_IF_HANDLE InterfaceUuid, void *Context)
{
    BOOL result, fIsImpersonated = FALSE, fIsRpcUserAdministrator = FALSE, fIsSamAccountNameFormat = FALSE;
    PSID pAdministratorsGroupSID = NULL;
    CHAR szTime[MAX_PATH];
    WCHAR wszRemoteUserUPN[MAX_PATH] = { 0 };
    DWORD cchRemoteUserUPN = MAX_PATH;
    HANDLE hImpersonationToken = 0;
    SID_IDENTIFIER_AUTHORITY NtAuthoritySID = SECURITY_NT_AUTHORITY;
    LeechSvc_GetTimeStamp(szTime);
    if(!AllocateAndInitializeSid(&NtAuthoritySID, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdministratorsGroupSID)) { goto fail; }
    if(RPC_S_OK != RpcImpersonateClient(Context)) { goto fail; }
    fIsImpersonated = TRUE;
    if(!GetUserNameExW(NameUserPrincipal, wszRemoteUserUPN, &cchRemoteUserUPN)) {
        fIsSamAccountNameFormat = GetUserNameExW(NameSamCompatible, wszRemoteUserUPN, &cchRemoteUserUPN);
    }
    if(!OpenThreadToken(GetCurrentThread(), TOKEN_READ, TRUE, &hImpersonationToken)) { goto fail; }
    result = CheckTokenMembership(hImpersonationToken, pAdministratorsGroupSID, &fIsRpcUserAdministrator);
    if(result && !fIsRpcUserAdministrator && fIsSamAccountNameFormat) {
        fIsRpcUserAdministrator = LeechSvcRpc_SecurityCallback_IsAdminNtlm(hImpersonationToken);
    }
    if(result && fIsRpcUserAdministrator) {
        LeechSvcRpc_WriteInfoEventLog("[%s] INFO: User authentication: '%S'\n", szTime, wszRemoteUserUPN);
    } else {
        LeechSvcRpc_WriteInfoEventLog("[%s] FAIL: User authentication: '%S' - not in Administrators group?\n", szTime, wszRemoteUserUPN);
        fIsRpcUserAdministrator = FALSE;
    }
fail:
    if(fIsImpersonated) {
        if(RPC_S_OK != RpcRevertToSelf()) {
            fIsRpcUserAdministrator = FALSE;
        }
    }
    if(hImpersonationToken) { CloseHandle(hImpersonationToken); }
    if(pAdministratorsGroupSID) { FreeSid(pAdministratorsGroupSID); }
    return fIsRpcUserAdministrator ? RPC_S_OK : RPC_S_ACCESS_DENIED;
}

RPC_STATUS CALLBACK LeechSvcRpc_SecurityCallback_AlwaysAllow(RPC_IF_HANDLE InterfaceUuid, void *Context)
{
    return RPC_S_OK;
}
#endif


VOID RpcStopGRPC()
{
    if(g_hGRPC) {
        g_pfn_leechgrpc_server_shutdown(g_hGRPC);
        g_hGRPC = NULL;
    }
}

//-----------------------------------------------------------------------------
// Minimal TCP message transport (keep-alive + worker-threaded) for LeechAgent.
//-----------------------------------------------------------------------------

static volatile LONG g_cHttpWorkers = 0;
#define HTTP_MAX_WORKERS        256
#define HTTP_SOCKET_BUFFER_SIZE (1024 * 1024)
#define HTTP_READMUX_MAX_INFLIGHT 4
#define HTTP_READSCATTER_WORKERS 8
#define HTTP_ASYNC_IO_WORKERS   4
#define HTTP_ASYNC_SEND_BURST_MAX 8
#define HTTP_CLIENT_IDLE_TIMEOUT_MS 6000
#define HTTP_FRAMEPOOL_MAGIC 0x46504f4c
#define HTTP_FRAMEPOOL_BUCKETS 6
typedef struct tdHTTP_SECURE_SEGMENT {
    const BYTE *pb;
    DWORD cb;
} HTTP_SECURE_SEGMENT, *PHTTP_SECURE_SEGMENT;

typedef struct tdHTTP_CLIENT_STATE {
    PBYTE pbIn;
    DWORD cbInAlloc;
    PBYTE pbTxFrame;
    DWORD cbTxFrameAlloc;
    PVOID hCryptoKeyEncrypt;
    PVOID hCryptoKeyDecrypt;
    PBYTE pbCryptoKeyObjectEncrypt;
    PBYTE pbCryptoKeyObjectDecrypt;
    DWORD cbCryptoKeyObjectEncrypt;
    DWORD cbCryptoKeyObjectDecrypt;
    BYTE rgbCryptoNonceBaseEncrypt[LEECHRPC_SECURE_NONCE_SIZE];
    BYTE rgbCryptoNonceBaseDecrypt[LEECHRPC_SECURE_NONCE_SIZE];
    QWORD qwCryptoSeqTx;
    QWORD qwCryptoSeqRx;
    BOOL fCryptoReady;
} HTTP_CLIENT_STATE, *PHTTP_CLIENT_STATE;

typedef struct tdHTTP_REDIRECT_SESSION HTTP_REDIRECT_SESSION, *PHTTP_REDIRECT_SESSION;
typedef struct tdHTTP_REDIRECT_WORKITEM {
    SOCKET sClient;
    PHTTP_REDIRECT_SESSION pSession;
} HTTP_REDIRECT_WORKITEM, *PHTTP_REDIRECT_WORKITEM;

typedef struct tdHTTP_CLIENT_CONNECTION HTTP_CLIENT_CONNECTION, *PHTTP_CLIENT_CONNECTION;
typedef struct tdHTTP_ASYNC_RECV_OP HTTP_ASYNC_RECV_OP, *PHTTP_ASYNC_RECV_OP;
typedef struct tdHTTP_ASYNC_SEND_OP HTTP_ASYNC_SEND_OP, *PHTTP_ASYNC_SEND_OP;

typedef enum tdHTTP_ASYNC_IO_OP_TYPE {
    HTTP_ASYNC_IO_OP_RECV = 1,
    HTTP_ASYNC_IO_OP_SEND = 2
} HTTP_ASYNC_IO_OP_TYPE;

typedef struct tdHTTP_ASYNC_IO_COMMON {
    OVERLAPPED Ov;
    DWORD dwOpType;
    PHTTP_CLIENT_CONNECTION pConn;
} HTTP_ASYNC_IO_COMMON, *PHTTP_ASYNC_IO_COMMON;

struct tdHTTP_ASYNC_SEND_OP {
    OVERLAPPED Ov;
    DWORD dwOpType;
    PHTTP_CLIENT_CONNECTION pConn;
    DWORD cBuffers;
    WSABUF WsaBuf[HTTP_ASYNC_SEND_BURST_MAX];
};

struct tdHTTP_CLIENT_CONNECTION {
    SOCKET sClient;
    HTTP_CLIENT_STATE State;
    CRITICAL_SECTION LockSendQueue;
    HANDLE hSendEvent;
    HANDLE hSendThread;
    DWORD dwSendThreadId;
    HANDLE hReadScatterSlots;
    HANDLE hAllReadScatterDone;
    volatile LONG cActiveReadScatter;
    volatile LONG cQueuedResponses;
    volatile LONG fStopSendThread;
    volatile LONG fSendFailed;
    volatile LONG fSendInFlight;
    volatile LONG cRef;
    volatile LONG fClosing;
    DWORD dwLastActivityTick;
    PHTTP_REDIRECT_SESSION pSession;
    PHTTP_ASYNC_RECV_OP pRecvOp;
    HTTP_ASYNC_SEND_OP SendOp;
    struct tdHTTP_SEND_ITEM *pSendHead;
    struct tdHTTP_SEND_ITEM *pSendTail;
};

typedef struct tdHTTP_READSCATTER_TASK {
    PHTTP_CLIENT_CONNECTION pConn;
    PBYTE pbPlain;
    DWORD cbPlain;
    struct tdHTTP_READSCATTER_TASK *Flink;
} HTTP_READSCATTER_TASK, *PHTTP_READSCATTER_TASK;

typedef struct tdHTTP_SEND_ITEM {
    PBYTE pbOut;
    DWORD cbOut;
    PBYTE pbFrame;
    DWORD cbFrame;
    DWORD cbSent;
    BOOL fFrameEmbeddedInResponse;
    struct tdHTTP_SEND_ITEM *Flink;
} HTTP_SEND_ITEM, *PHTTP_SEND_ITEM;

struct tdHTTP_ASYNC_RECV_OP {
    OVERLAPPED Ov;
    DWORD dwOpType;
    PHTTP_CLIENT_CONNECTION pConn;
    BOOL fRecvHeader;
    DWORD cbExpected;
    DWORD cbReceived;
    LEECHRPC_SECURE_FRAME_HDR Hdr;
    BYTE rgbHdr[sizeof(LEECHRPC_SECURE_FRAME_HDR)];
    PBYTE pbPayload;
    DWORD cbPayloadAlloc;
};

struct tdHTTP_REDIRECT_SESSION {
    SOCKET sListen;
    SOCKADDR_STORAGE Peer;
    INT cbPeer;
    DWORD dwPort;
    BYTE rgbToken[LEECHRPC_REDIRECT_TOKEN_SIZE];
    volatile LONG cRef;
    volatile LONG fStop;
    volatile LONG cActiveClients;
    DWORD dwLastActivityTick;
};

static VOID Http_ConfigureClientSocket(_In_ SOCKET sClient);
static BOOL Http_HandleClient(_In_ SOCKET sClient, _Inout_ PHTTP_CLIENT_STATE pState, _In_ PHTTP_REDIRECT_SESSION pSession);
static BOOL Http_ProcessPlainRequest(_In_reads_bytes_(cbPlain) PBYTE pbPlain, _In_ DWORD cbPlain, _Out_ PBYTE *ppbOut, _Out_ SIZE_T *pcbOut);
static VOID Http_ConnAddRef(_Inout_ PHTTP_CLIENT_CONNECTION pConn);
static VOID Http_ConnClose(_Inout_ PHTTP_CLIENT_CONNECTION pConn);
static VOID Http_ConnRelease(_Inout_ PHTTP_CLIENT_CONNECTION pConn);
static BOOL Http_ConnIsIdleTimedOut(_In_ PHTTP_CLIENT_CONNECTION pConn);
static VOID Http_UpdateReadScatterDone(_Inout_ PHTTP_CLIENT_CONNECTION pConn);
static BOOL Http_DispatchPlainMessage(_Inout_ PHTTP_CLIENT_CONNECTION pConn, _In_reads_bytes_(cbPlain) PBYTE pbPlain, _In_ DWORD cbPlain);
static BOOL Http_AsyncPostRecv(_Inout_ PHTTP_CLIENT_CONNECTION pConn);
static BOOL Http_AsyncKickSendLocked(_Inout_ PHTTP_CLIENT_CONNECTION pConn);
static DWORD WINAPI Http_AsyncIoWorker(_In_ LPVOID lpParameter);
static BOOL Http_AsyncIoStart();
static VOID Http_AsyncIoStop();

static CRITICAL_SECTION g_HttpReadScatterQueueLock;
static HANDLE g_hHttpReadScatterQueueSem = NULL;
static HANDLE g_ahHttpReadScatterWorkers[HTTP_READSCATTER_WORKERS] = { 0 };
static volatile LONG g_fHttpReadScatterWorkersInitialized = FALSE;
static volatile LONG g_fHttpReadScatterWorkersStop = FALSE;
static PHTTP_READSCATTER_TASK g_pHttpReadScatterQueueHead = NULL;
static PHTTP_READSCATTER_TASK g_pHttpReadScatterQueueTail = NULL;
static HANDLE g_hHttpAsyncIoCp = NULL;
static HANDLE g_ahHttpAsyncIoWorkers[HTTP_ASYNC_IO_WORKERS] = { 0 };
static volatile LONG g_fHttpAsyncIoInitialized = FALSE;
static volatile LONG g_fHttpAsyncIoStop = FALSE;
static CRITICAL_SECTION g_HttpFramePoolLock;
static volatile LONG g_fHttpFramePoolInitialized = FALSE;

typedef struct tdHTTP_FRAME_POOL_HDR {
    DWORD dwMagic;
    DWORD iBucket;
    DWORD cbCapacity;
    struct tdHTTP_FRAME_POOL_HDR *Flink;
} HTTP_FRAME_POOL_HDR, *PHTTP_FRAME_POOL_HDR;

static const DWORD g_cbHttpFramePoolBuckets[HTTP_FRAMEPOOL_BUCKETS] = {
    0x00001000, 0x00010000, 0x00040000, 0x00100000, 0x00400000, 0x01000000
};
static const DWORD g_cHttpFramePoolBucketMax[HTTP_FRAMEPOOL_BUCKETS] = {
    64, 32, 16, 8, 4, 2
};
static PHTTP_FRAME_POOL_HDR g_HttpFramePoolHead[HTTP_FRAMEPOOL_BUCKETS] = { 0 };
static DWORD g_cHttpFramePoolCount[HTTP_FRAMEPOOL_BUCKETS] = { 0 };

static const BYTE g_HttpSecurePsk[32] = {
    0x6d, 0x2a, 0x4f, 0x91, 0xc3, 0x7b, 0x11, 0xe8,
    0x52, 0x39, 0xaa, 0x6f, 0x0d, 0xb4, 0x83, 0x1c,
    0x74, 0xde, 0x25, 0x90, 0x4a, 0xf2, 0x68, 0x17,
    0xbe, 0x33, 0x5c, 0x8d, 0xe1, 0x46, 0x79, 0x0b
};

static BCRYPT_ALG_HANDLE g_hHttpSecureAlgAes = NULL;
static BCRYPT_ALG_HANDLE g_hHttpSecureAlgHmac = NULL;
static INIT_ONCE g_HttpSecureInitOnce = INIT_ONCE_STATIC_INIT;

static BOOL Http_SendAll(_In_ SOCKET s, _In_reads_bytes_(cbData) const BYTE *pbData, _In_ SIZE_T cbData)
{
    SIZE_T cbSentTotal = 0;
    while(cbSentTotal < cbData) {
        WSABUF wsaBuf;
        DWORD cbSent = 0;
        wsaBuf.buf = (CHAR*)pbData + cbSentTotal;
        wsaBuf.len = (ULONG)(cbData - cbSentTotal);
        if(WSASend(s, &wsaBuf, 1, &cbSent, 0, NULL, NULL) == SOCKET_ERROR || cbSent == 0) {
            return FALSE;
        }
        cbSentTotal += cbSent;
    }
    return TRUE;
}

static DWORD Http_FramePoolBucketIndex(_In_ DWORD cb)
{
    DWORD i;
    for(i = 0; i < HTTP_FRAMEPOOL_BUCKETS; i++) {
        if(cb <= g_cbHttpFramePoolBuckets[i]) {
            return i;
        }
    }
    return (DWORD)-1;
}

static PBYTE Http_FramePoolAlloc(_In_ DWORD cb)
{
    DWORD iBucket = Http_FramePoolBucketIndex(cb);
    PHTTP_FRAME_POOL_HDR pHdr = NULL;
    if(g_fHttpFramePoolInitialized && (iBucket != (DWORD)-1)) {
        EnterCriticalSection(&g_HttpFramePoolLock);
        pHdr = g_HttpFramePoolHead[iBucket];
        if(pHdr) {
            g_HttpFramePoolHead[iBucket] = pHdr->Flink;
            g_cHttpFramePoolCount[iBucket]--;
            pHdr->Flink = NULL;
        }
        LeaveCriticalSection(&g_HttpFramePoolLock);
    }
    if(!pHdr) {
        DWORD cbCapacity = (iBucket != (DWORD)-1) ? g_cbHttpFramePoolBuckets[iBucket] : cb;
        pHdr = (PHTTP_FRAME_POOL_HDR)LocalAlloc(LMEM_FIXED, sizeof(HTTP_FRAME_POOL_HDR) + cbCapacity);
        if(!pHdr) {
            return NULL;
        }
        pHdr->dwMagic = HTTP_FRAMEPOOL_MAGIC;
        pHdr->iBucket = iBucket;
        pHdr->cbCapacity = cbCapacity;
        pHdr->Flink = NULL;
    }
    return (PBYTE)(pHdr + 1);
}

static VOID Http_FramePoolFree(_Pre_maybenull_ PBYTE pb)
{
    PHTTP_FRAME_POOL_HDR pHdr;
    if(!pb) { return; }
    pHdr = ((PHTTP_FRAME_POOL_HDR)pb) - 1;
    if((pHdr->dwMagic != HTTP_FRAMEPOOL_MAGIC) || (pHdr->iBucket >= HTTP_FRAMEPOOL_BUCKETS) || !g_fHttpFramePoolInitialized) {
        LocalFree(pHdr);
        return;
    }
    EnterCriticalSection(&g_HttpFramePoolLock);
    if(g_cHttpFramePoolCount[pHdr->iBucket] >= g_cHttpFramePoolBucketMax[pHdr->iBucket]) {
        LeaveCriticalSection(&g_HttpFramePoolLock);
        LocalFree(pHdr);
        return;
    }
    pHdr->Flink = g_HttpFramePoolHead[pHdr->iBucket];
    g_HttpFramePoolHead[pHdr->iBucket] = pHdr;
    g_cHttpFramePoolCount[pHdr->iBucket]++;
    LeaveCriticalSection(&g_HttpFramePoolLock);
}

static BOOL Http_RecvAll(_In_ SOCKET s, _Out_writes_bytes_(cbData) BYTE *pbData, _In_ DWORD cbData)
{
    DWORD cbRecvTotal = 0;
    while(cbRecvTotal < cbData) {
        WSABUF wsaBuf;
        DWORD cbRecv = 0;
        DWORD dwFlags = 0;
        wsaBuf.buf = (CHAR*)pbData + cbRecvTotal;
        wsaBuf.len = cbData - cbRecvTotal;
        if(WSARecv(s, &wsaBuf, 1, &cbRecv, &dwFlags, NULL, NULL) == SOCKET_ERROR || cbRecv == 0) {
            if((cbRecvTotal == 0) && (WSAGetLastError() == WSAETIMEDOUT)) {
                return FALSE;
            }
            return FALSE;
        }
        cbRecvTotal += cbRecv;
    }
    return TRUE;
}

static BOOL CALLBACK Http_SecureInitializeProviders(_In_ PINIT_ONCE InitOnce, _In_opt_ PVOID Parameter, _Out_opt_ PVOID *Context)
{
    NTSTATUS nt = 0;
    UNREFERENCED_PARAMETER(InitOnce);
    UNREFERENCED_PARAMETER(Parameter);
    UNREFERENCED_PARAMETER(Context);
    nt = BCryptOpenAlgorithmProvider(&g_hHttpSecureAlgAes, BCRYPT_AES_ALGORITHM, NULL, 0);
    if(!BCRYPT_SUCCESS(nt)) { goto fail; }
    nt = BCryptSetProperty(
        g_hHttpSecureAlgAes,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        (ULONG)((wcslen(BCRYPT_CHAIN_MODE_GCM) + 1) * sizeof(WCHAR)),
        0);
    if(!BCRYPT_SUCCESS(nt)) { goto fail; }
    nt = BCryptOpenAlgorithmProvider(&g_hHttpSecureAlgHmac, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if(!BCRYPT_SUCCESS(nt)) { goto fail; }
    return TRUE;
fail:
    if(g_hHttpSecureAlgAes) {
        BCryptCloseAlgorithmProvider(g_hHttpSecureAlgAes, 0);
        g_hHttpSecureAlgAes = NULL;
    }
    if(g_hHttpSecureAlgHmac) {
        BCryptCloseAlgorithmProvider(g_hHttpSecureAlgHmac, 0);
        g_hHttpSecureAlgHmac = NULL;
    }
    return FALSE;
}

static BOOL Http_SecureEnsureInitialized()
{
    return InitOnceExecuteOnce(&g_HttpSecureInitOnce, Http_SecureInitializeProviders, NULL, NULL) ? TRUE : FALSE;
}

static VOID Http_SecureDestroyState(_Inout_ PHTTP_CLIENT_STATE pState)
{
    if(pState->hCryptoKeyEncrypt) {
        BCryptDestroyKey((BCRYPT_KEY_HANDLE)pState->hCryptoKeyEncrypt);
        pState->hCryptoKeyEncrypt = NULL;
    }
    if(pState->hCryptoKeyDecrypt) {
        BCryptDestroyKey((BCRYPT_KEY_HANDLE)pState->hCryptoKeyDecrypt);
        pState->hCryptoKeyDecrypt = NULL;
    }
    if(pState->pbCryptoKeyObjectEncrypt) {
        SecureZeroMemory(pState->pbCryptoKeyObjectEncrypt, pState->cbCryptoKeyObjectEncrypt);
        LocalFree(pState->pbCryptoKeyObjectEncrypt);
        pState->pbCryptoKeyObjectEncrypt = NULL;
    }
    if(pState->pbCryptoKeyObjectDecrypt) {
        SecureZeroMemory(pState->pbCryptoKeyObjectDecrypt, pState->cbCryptoKeyObjectDecrypt);
        LocalFree(pState->pbCryptoKeyObjectDecrypt);
        pState->pbCryptoKeyObjectDecrypt = NULL;
    }
    pState->cbCryptoKeyObjectEncrypt = 0;
    pState->cbCryptoKeyObjectDecrypt = 0;
    if(pState->pbTxFrame) {
        SecureZeroMemory(pState->pbTxFrame, pState->cbTxFrameAlloc);
        LocalFree(pState->pbTxFrame);
        pState->pbTxFrame = NULL;
    }
    pState->cbTxFrameAlloc = 0;
    SecureZeroMemory(pState->rgbCryptoNonceBaseEncrypt, sizeof(pState->rgbCryptoNonceBaseEncrypt));
    SecureZeroMemory(pState->rgbCryptoNonceBaseDecrypt, sizeof(pState->rgbCryptoNonceBaseDecrypt));
    pState->qwCryptoSeqTx = 0;
    pState->qwCryptoSeqRx = 0;
    pState->fCryptoReady = FALSE;
}

static BOOL Http_SecureEnsureTxFrame(_Inout_ PHTTP_CLIENT_STATE pState, _In_ DWORD cbFrame)
{
    PBYTE pbNew;
    DWORD cbAlloc;
    if(cbFrame <= pState->cbTxFrameAlloc) {
        return TRUE;
    }
    cbAlloc = max(cbFrame, 0x4000U);
    pbNew = (PBYTE)LocalAlloc(LMEM_FIXED, cbAlloc);
    if(!pbNew) {
        return FALSE;
    }
    if(pState->pbTxFrame) {
        SecureZeroMemory(pState->pbTxFrame, pState->cbTxFrameAlloc);
        LocalFree(pState->pbTxFrame);
    }
    pState->pbTxFrame = pbNew;
    pState->cbTxFrameAlloc = cbAlloc;
    return TRUE;
}

static BOOL Http_SecureHmacSha256(
    _In_reads_bytes_(cbKey) const BYTE *pbKey,
    _In_ DWORD cbKey,
    _In_reads_(cSeg) const HTTP_SECURE_SEGMENT *pSeg,
    _In_ DWORD cSeg,
    _Out_writes_bytes_(LEECHRPC_SECURE_MAC_SIZE) BYTE *rgbMac)
{
    NTSTATUS nt;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PBYTE pbHashObject = NULL;
    DWORD i;
    ULONG cbHashObject = 0, cbResult = 0;
    if(!Http_SecureEnsureInitialized()) { return FALSE; }
    nt = BCryptGetProperty(g_hHttpSecureAlgHmac, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbHashObject, sizeof(cbHashObject), &cbResult, 0);
    if(!BCRYPT_SUCCESS(nt) || !cbHashObject) { return FALSE; }
    pbHashObject = (PBYTE)LocalAlloc(0, cbHashObject);
    if(!pbHashObject) { return FALSE; }
    nt = BCryptCreateHash(g_hHttpSecureAlgHmac, &hHash, pbHashObject, cbHashObject, (PUCHAR)pbKey, cbKey, 0);
    if(!BCRYPT_SUCCESS(nt)) { goto fail; }
    for(i = 0; i < cSeg; i++) {
        if(pSeg[i].pb && pSeg[i].cb) {
            nt = BCryptHashData(hHash, (PUCHAR)pSeg[i].pb, pSeg[i].cb, 0);
            if(!BCRYPT_SUCCESS(nt)) { goto fail; }
        }
    }
    nt = BCryptFinishHash(hHash, rgbMac, LEECHRPC_SECURE_MAC_SIZE, 0);
    if(!BCRYPT_SUCCESS(nt)) { goto fail; }
    BCryptDestroyHash(hHash);
    SecureZeroMemory(pbHashObject, cbHashObject);
    LocalFree(pbHashObject);
    return TRUE;
fail:
    if(hHash) { BCryptDestroyHash(hHash); }
    if(pbHashObject) {
        SecureZeroMemory(pbHashObject, cbHashObject);
        LocalFree(pbHashObject);
    }
    return FALSE;
}

static BOOL Http_SecureCreateKey(
    _In_reads_bytes_(LEECHRPC_SECURE_MAC_SIZE) const BYTE *pbKeyMaterial,
    _Out_ PVOID *phKey,
    _Outptr_result_bytebuffer_(*pcbKeyObject) PBYTE *ppbKeyObject,
    _Out_ DWORD *pcbKeyObject)
{
    NTSTATUS nt;
    BCRYPT_KEY_HANDLE hKey = NULL;
    PBYTE pbKeyObject = NULL;
    ULONG cbKeyObject = 0, cbResult = 0;
    *phKey = NULL;
    *ppbKeyObject = NULL;
    *pcbKeyObject = 0;
    if(!Http_SecureEnsureInitialized()) { return FALSE; }
    nt = BCryptGetProperty(g_hHttpSecureAlgAes, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObject, sizeof(cbKeyObject), &cbResult, 0);
    if(!BCRYPT_SUCCESS(nt) || !cbKeyObject) { return FALSE; }
    pbKeyObject = (PBYTE)LocalAlloc(0, cbKeyObject);
    if(!pbKeyObject) { return FALSE; }
    nt = BCryptGenerateSymmetricKey(g_hHttpSecureAlgAes, &hKey, pbKeyObject, cbKeyObject, (PUCHAR)pbKeyMaterial, LEECHRPC_SECURE_MAC_SIZE, 0);
    if(!BCRYPT_SUCCESS(nt)) {
        SecureZeroMemory(pbKeyObject, cbKeyObject);
        LocalFree(pbKeyObject);
        return FALSE;
    }
    *phKey = hKey;
    *ppbKeyObject = pbKeyObject;
    *pcbKeyObject = cbKeyObject;
    return TRUE;
}

static VOID Http_SecureBuildNonce(_In_reads_bytes_(LEECHRPC_SECURE_NONCE_SIZE) const BYTE *pbBase, _In_ QWORD qwSeq, _Out_writes_bytes_(LEECHRPC_SECURE_NONCE_SIZE) BYTE *pbNonce)
{
    DWORD i;
    memcpy(pbNonce, pbBase, LEECHRPC_SECURE_NONCE_SIZE);
    for(i = 0; i < sizeof(QWORD); i++) {
        pbNonce[LEECHRPC_SECURE_NONCE_SIZE - 1 - i] ^= (BYTE)(qwSeq >> (8 * i));
    }
}

static BOOL Http_SecureDeriveConnectionKeys(
    _In_reads_bytes_(LEECHRPC_SECURE_RANDOM_SIZE) const BYTE *pbClientRandom,
    _In_reads_bytes_(LEECHRPC_SECURE_RANDOM_SIZE) const BYTE *pbServerRandom,
    _Out_writes_bytes_(LEECHRPC_SECURE_MAC_SIZE) BYTE *pbKeyEncrypt,
    _Out_writes_bytes_(LEECHRPC_SECURE_MAC_SIZE) BYTE *pbKeyDecrypt,
    _Out_writes_bytes_(LEECHRPC_SECURE_NONCE_SIZE) BYTE *pbNonceEncrypt,
    _Out_writes_bytes_(LEECHRPC_SECURE_NONCE_SIZE) BYTE *pbNonceDecrypt)
{
    static const BYTE szKeyC2S[] = "rv-key-c2s";
    static const BYTE szKeyS2C[] = "rv-key-s2c";
    static const BYTE szNonceC2S[] = "rv-nonce-c2s";
    static const BYTE szNonceS2C[] = "rv-nonce-s2c";
    HTTP_SECURE_SEGMENT Seg[3];
    BYTE rgbTmp[LEECHRPC_SECURE_MAC_SIZE];
    Seg[1].pb = pbClientRandom;
    Seg[1].cb = LEECHRPC_SECURE_RANDOM_SIZE;
    Seg[2].pb = pbServerRandom;
    Seg[2].cb = LEECHRPC_SECURE_RANDOM_SIZE;
    Seg[0].pb = szKeyS2C;
    Seg[0].cb = sizeof(szKeyS2C) - 1;
    if(!Http_SecureHmacSha256(g_HttpSecurePsk, sizeof(g_HttpSecurePsk), Seg, 3, pbKeyEncrypt)) { return FALSE; }
    Seg[0].pb = szKeyC2S;
    Seg[0].cb = sizeof(szKeyC2S) - 1;
    if(!Http_SecureHmacSha256(g_HttpSecurePsk, sizeof(g_HttpSecurePsk), Seg, 3, pbKeyDecrypt)) { return FALSE; }
    Seg[0].pb = szNonceS2C;
    Seg[0].cb = sizeof(szNonceS2C) - 1;
    if(!Http_SecureHmacSha256(g_HttpSecurePsk, sizeof(g_HttpSecurePsk), Seg, 3, rgbTmp)) { return FALSE; }
    memcpy(pbNonceEncrypt, rgbTmp, LEECHRPC_SECURE_NONCE_SIZE);
    Seg[0].pb = szNonceC2S;
    Seg[0].cb = sizeof(szNonceC2S) - 1;
    if(!Http_SecureHmacSha256(g_HttpSecurePsk, sizeof(g_HttpSecurePsk), Seg, 3, rgbTmp)) { return FALSE; }
    memcpy(pbNonceDecrypt, rgbTmp, LEECHRPC_SECURE_NONCE_SIZE);
    SecureZeroMemory(rgbTmp, sizeof(rgbTmp));
    return TRUE;
}

static BOOL Http_SecureHandshake(_In_ SOCKET sClient, _Inout_ PHTTP_CLIENT_STATE pState)
{
    static const BYTE szHelloClient[] = "rv-hello-client";
    static const BYTE szHelloServer[] = "rv-hello-server";
    LEECHRPC_SECURE_HELLO HelloClient = { 0 };
    LEECHRPC_SECURE_HELLO HelloServer = { 0 };
    HTTP_SECURE_SEGMENT Seg[3];
    BYTE rgbMacExpected[LEECHRPC_SECURE_MAC_SIZE];
    BYTE rgbKeyEncrypt[LEECHRPC_SECURE_MAC_SIZE];
    BYTE rgbKeyDecrypt[LEECHRPC_SECURE_MAC_SIZE];
    BYTE rgbNonceEncrypt[LEECHRPC_SECURE_NONCE_SIZE];
    BYTE rgbNonceDecrypt[LEECHRPC_SECURE_NONCE_SIZE];
    if(pState->fCryptoReady) { return TRUE; }
    if(!Http_SecureEnsureInitialized()) { return FALSE; }
    if(!Http_RecvAll(sClient, (PBYTE)&HelloClient, sizeof(HelloClient))) { goto fail; }
    if((HelloClient.dwMagic != LEECHRPC_SECURE_HELLO_CLIENT_MAGIC) || (HelloClient.dwVersion != LEECHRPC_SECURE_VERSION)) { goto fail; }
    Seg[0].pb = szHelloClient;
    Seg[0].cb = sizeof(szHelloClient) - 1;
    Seg[1].pb = (const BYTE*)&HelloClient.dwVersion;
    Seg[1].cb = sizeof(HelloClient.dwVersion);
    Seg[2].pb = HelloClient.rgbRandom;
    Seg[2].cb = sizeof(HelloClient.rgbRandom);
    if(!Http_SecureHmacSha256(g_HttpSecurePsk, sizeof(g_HttpSecurePsk), Seg, 3, rgbMacExpected)) { goto fail; }
    if(memcmp(rgbMacExpected, HelloClient.rgbMac, sizeof(rgbMacExpected))) { goto fail; }
    HelloServer.dwMagic = LEECHRPC_SECURE_HELLO_SERVER_MAGIC;
    HelloServer.dwVersion = LEECHRPC_SECURE_VERSION;
    if(!BCRYPT_SUCCESS(BCryptGenRandom(NULL, HelloServer.rgbRandom, sizeof(HelloServer.rgbRandom), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) { goto fail; }
    Seg[0].pb = szHelloServer;
    Seg[0].cb = sizeof(szHelloServer) - 1;
    Seg[1].pb = HelloClient.rgbRandom;
    Seg[1].cb = sizeof(HelloClient.rgbRandom);
    Seg[2].pb = HelloServer.rgbRandom;
    Seg[2].cb = sizeof(HelloServer.rgbRandom);
    if(!Http_SecureHmacSha256(g_HttpSecurePsk, sizeof(g_HttpSecurePsk), Seg, 3, HelloServer.rgbMac)) { goto fail; }
    if(!Http_SendAll(sClient, (const BYTE*)&HelloServer, sizeof(HelloServer))) { goto fail; }
    if(!Http_SecureDeriveConnectionKeys(HelloClient.rgbRandom, HelloServer.rgbRandom, rgbKeyEncrypt, rgbKeyDecrypt, rgbNonceEncrypt, rgbNonceDecrypt)) { goto fail; }
    if(!Http_SecureCreateKey(rgbKeyEncrypt, &pState->hCryptoKeyEncrypt, &pState->pbCryptoKeyObjectEncrypt, &pState->cbCryptoKeyObjectEncrypt)) { goto fail; }
    if(!Http_SecureCreateKey(rgbKeyDecrypt, &pState->hCryptoKeyDecrypt, &pState->pbCryptoKeyObjectDecrypt, &pState->cbCryptoKeyObjectDecrypt)) { goto fail; }
    memcpy(pState->rgbCryptoNonceBaseEncrypt, rgbNonceEncrypt, sizeof(rgbNonceEncrypt));
    memcpy(pState->rgbCryptoNonceBaseDecrypt, rgbNonceDecrypt, sizeof(rgbNonceDecrypt));
    pState->qwCryptoSeqTx = 0;
    pState->qwCryptoSeqRx = 0;
    pState->fCryptoReady = TRUE;
    SecureZeroMemory(rgbMacExpected, sizeof(rgbMacExpected));
    SecureZeroMemory(rgbKeyEncrypt, sizeof(rgbKeyEncrypt));
    SecureZeroMemory(rgbKeyDecrypt, sizeof(rgbKeyDecrypt));
    SecureZeroMemory(rgbNonceEncrypt, sizeof(rgbNonceEncrypt));
    SecureZeroMemory(rgbNonceDecrypt, sizeof(rgbNonceDecrypt));
    SecureZeroMemory(&HelloClient, sizeof(HelloClient));
    SecureZeroMemory(&HelloServer, sizeof(HelloServer));
    return TRUE;
fail:
    Http_SecureDestroyState(pState);
    SecureZeroMemory(rgbMacExpected, sizeof(rgbMacExpected));
    SecureZeroMemory(rgbKeyEncrypt, sizeof(rgbKeyEncrypt));
    SecureZeroMemory(rgbKeyDecrypt, sizeof(rgbKeyDecrypt));
    SecureZeroMemory(rgbNonceEncrypt, sizeof(rgbNonceEncrypt));
    SecureZeroMemory(rgbNonceDecrypt, sizeof(rgbNonceDecrypt));
    SecureZeroMemory(&HelloClient, sizeof(HelloClient));
    SecureZeroMemory(&HelloServer, sizeof(HelloServer));
    return FALSE;
}

static BOOL Http_SecureSendMessage(
    _In_ SOCKET sClient,
    _Inout_ PHTTP_CLIENT_STATE pState,
    _In_reads_bytes_(cbPlain) const BYTE *pbPlain,
    _In_ DWORD cbPlain)
{
    NTSTATUS nt;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO AuthInfo;
    LEECHRPC_SECURE_FRAME_HDR Hdr = { 0 };
    PBYTE pbFrame;
    PBYTE pbCipher;
    PBYTE pbTag;
    BYTE rgbNonce[LEECHRPC_SECURE_NONCE_SIZE];
    ULONG cbOut = 0;
    Hdr.dwMagic = LEECHRPC_SECURE_FRAME_MAGIC;
    Hdr.dwVersion = LEECHRPC_SECURE_VERSION;
    Hdr.qwSeq = ++pState->qwCryptoSeqTx;
    Hdr.cbFrame = sizeof(LEECHRPC_SECURE_FRAME_HDR) + cbPlain + LEECHRPC_SECURE_TAG_SIZE;
    if(!Http_SecureEnsureTxFrame(pState, Hdr.cbFrame)) { return FALSE; }
    pbFrame = pState->pbTxFrame;
    memcpy(pbFrame, &Hdr, sizeof(Hdr));
    pbCipher = pbFrame + sizeof(Hdr);
    pbTag = pbCipher + cbPlain;
    Http_SecureBuildNonce(pState->rgbCryptoNonceBaseEncrypt, Hdr.qwSeq, rgbNonce);
    BCRYPT_INIT_AUTH_MODE_INFO(AuthInfo);
    AuthInfo.pbNonce = rgbNonce;
    AuthInfo.cbNonce = sizeof(rgbNonce);
    AuthInfo.pbAuthData = pbFrame;
    AuthInfo.cbAuthData = sizeof(Hdr);
    AuthInfo.pbTag = pbTag;
    AuthInfo.cbTag = LEECHRPC_SECURE_TAG_SIZE;
    nt = BCryptEncrypt((BCRYPT_KEY_HANDLE)pState->hCryptoKeyEncrypt, (PUCHAR)pbPlain, cbPlain, &AuthInfo, NULL, 0, pbCipher, cbPlain, &cbOut, 0);
    SecureZeroMemory(rgbNonce, sizeof(rgbNonce));
    if(!BCRYPT_SUCCESS(nt) || (cbOut != cbPlain)) {
        return FALSE;
    }
    return Http_SendAll(sClient, pbFrame, Hdr.cbFrame);
}

static BOOL Http_SecureBuildMessageFrame(
    _Inout_ PHTTP_CLIENT_STATE pState,
    _In_reads_bytes_(cbPlain) const BYTE *pbPlain,
    _In_ DWORD cbPlain,
    _Outptr_result_bytebuffer_(*pcbFrame) PBYTE *ppbFrame,
    _Out_ DWORD *pcbFrame)
{
    NTSTATUS nt;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO AuthInfo;
    LEECHRPC_SECURE_FRAME_HDR Hdr = { 0 };
    PLEECHRPC_MSG_HDR pMsgHdr = (PLEECHRPC_MSG_HDR)pbPlain;
    PBYTE pbFrame = NULL;
    PBYTE pbCipher;
    PBYTE pbTag;
    BYTE rgbNonce[LEECHRPC_SECURE_NONCE_SIZE];
    ULONG cbOut = 0;
    *ppbFrame = NULL;
    *pcbFrame = 0;
    Hdr.dwMagic = LEECHRPC_SECURE_FRAME_MAGIC;
    Hdr.dwVersion = LEECHRPC_SECURE_VERSION;
    Hdr.qwSeq = ++pState->qwCryptoSeqTx;
    Hdr.cbFrame = sizeof(LEECHRPC_SECURE_FRAME_HDR) + cbPlain + LEECHRPC_SECURE_TAG_SIZE;
    /*
    * READSCATTER responses are the hottest path, but the embedded-frame branch
    * is also the newest and most failure-prone path. Keep the response pool,
    * but fall back to a separate frame buffer here until the in-place path is
    * validated end-to-end under real traffic.
    */
    if(((cbPlain >= sizeof(LEECHRPC_MSG_HDR)) && (pMsgHdr->tpMsg == LEECHRPC_MSGTYPE_READSCATTER_RSP)) ||
        !LeechRpc_ServerResponseGetFrameBuffer((PBYTE)pbPlain, cbPlain, &pbFrame, pcbFrame)) {
        if(!(pbFrame = Http_FramePoolAlloc(Hdr.cbFrame))) {
            return FALSE;
        }
        *pcbFrame = Hdr.cbFrame;
    }
    memcpy(pbFrame, &Hdr, sizeof(Hdr));
    pbCipher = pbFrame + sizeof(Hdr);
    pbTag = pbCipher + cbPlain;
    Http_SecureBuildNonce(pState->rgbCryptoNonceBaseEncrypt, Hdr.qwSeq, rgbNonce);
    BCRYPT_INIT_AUTH_MODE_INFO(AuthInfo);
    AuthInfo.pbNonce = rgbNonce;
    AuthInfo.cbNonce = sizeof(rgbNonce);
    AuthInfo.pbAuthData = pbFrame;
    AuthInfo.cbAuthData = sizeof(Hdr);
    AuthInfo.pbTag = pbTag;
    AuthInfo.cbTag = LEECHRPC_SECURE_TAG_SIZE;
    if(pbCipher != pbPlain) {
        memcpy(pbCipher, pbPlain, cbPlain);
    }
    nt = BCryptEncrypt((BCRYPT_KEY_HANDLE)pState->hCryptoKeyEncrypt, pbCipher, cbPlain, &AuthInfo, NULL, 0, pbCipher, cbPlain, &cbOut, 0);
    SecureZeroMemory(rgbNonce, sizeof(rgbNonce));
    if(!BCRYPT_SUCCESS(nt) || (cbOut != cbPlain)) {
        if(pbCipher != pbPlain) {
            Http_FramePoolFree(pbFrame);
        }
        return FALSE;
    }
    *ppbFrame = pbFrame;
    *pcbFrame = Hdr.cbFrame;
    return TRUE;
}

static BOOL Http_SecureRecvMessage(
    _In_ SOCKET sClient,
    _Inout_ PHTTP_CLIENT_STATE pState,
    _Outptr_result_bytebuffer_(*pcbPlain) PBYTE *ppbPlain,
    _Out_ DWORD *pcbPlain)
{
    NTSTATUS nt;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO AuthInfo;
    LEECHRPC_SECURE_FRAME_HDR Hdr = { 0 };
    PBYTE pbPayload = NULL;
    PBYTE pbPlain = NULL;
    BYTE rgbNonce[LEECHRPC_SECURE_NONCE_SIZE];
    DWORD cbCipher;
    ULONG cbOut = 0;
    if(!Http_RecvAll(sClient, (PBYTE)&Hdr, sizeof(Hdr))) { return FALSE; }
    if((Hdr.dwMagic != LEECHRPC_SECURE_FRAME_MAGIC) || (Hdr.dwVersion != LEECHRPC_SECURE_VERSION) || (Hdr.cbFrame < sizeof(Hdr) + LEECHRPC_SECURE_TAG_SIZE + sizeof(LEECHRPC_MSG_HDR)) || (Hdr.cbFrame >= 0x10000000) || (Hdr.qwSeq != (pState->qwCryptoSeqRx + 1))) {
        return FALSE;
    }
    cbCipher = Hdr.cbFrame - sizeof(Hdr) - LEECHRPC_SECURE_TAG_SIZE;
    pbPayload = (PBYTE)LocalAlloc(LMEM_FIXED, cbCipher + LEECHRPC_SECURE_TAG_SIZE);
    pbPlain = (PBYTE)LocalAlloc(LMEM_FIXED, cbCipher);
    if(!pbPayload || !pbPlain) { goto fail; }
    if(!Http_RecvAll(sClient, pbPayload, cbCipher + LEECHRPC_SECURE_TAG_SIZE)) { goto fail; }
    Http_SecureBuildNonce(pState->rgbCryptoNonceBaseDecrypt, Hdr.qwSeq, rgbNonce);
    BCRYPT_INIT_AUTH_MODE_INFO(AuthInfo);
    AuthInfo.pbNonce = rgbNonce;
    AuthInfo.cbNonce = sizeof(rgbNonce);
    AuthInfo.pbAuthData = (PUCHAR)&Hdr;
    AuthInfo.cbAuthData = sizeof(Hdr);
    AuthInfo.pbTag = pbPayload + cbCipher;
    AuthInfo.cbTag = LEECHRPC_SECURE_TAG_SIZE;
    nt = BCryptDecrypt((BCRYPT_KEY_HANDLE)pState->hCryptoKeyDecrypt, pbPayload, cbCipher, &AuthInfo, NULL, 0, pbPlain, cbCipher, &cbOut, 0);
    SecureZeroMemory(rgbNonce, sizeof(rgbNonce));
    if(!BCRYPT_SUCCESS(nt) || (cbOut != cbCipher)) { goto fail; }
    pState->qwCryptoSeqRx = Hdr.qwSeq;
    LocalFree(pbPayload);
    *ppbPlain = pbPlain;
    *pcbPlain = cbCipher;
    return TRUE;
fail:
    LocalFree(pbPayload);
    LocalFree(pbPlain);
    return FALSE;
}

static BOOL Http_SecureDecryptReceivedMessage(
    _Inout_ PHTTP_CLIENT_STATE pState,
    _In_ PLEECHRPC_SECURE_FRAME_HDR pHdr,
    _In_reads_bytes_(cbPayload) PBYTE pbPayload,
    _In_ DWORD cbPayload,
    _Outptr_result_bytebuffer_(*pcbPlain) PBYTE *ppbPlain,
    _Out_ DWORD *pcbPlain)
{
    NTSTATUS nt;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO AuthInfo;
    PBYTE pbPlain = NULL;
    BYTE rgbNonce[LEECHRPC_SECURE_NONCE_SIZE];
    DWORD cbCipher;
    ULONG cbOut = 0;
    *ppbPlain = NULL;
    *pcbPlain = 0;
    if((pHdr->dwMagic != LEECHRPC_SECURE_FRAME_MAGIC) ||
        (pHdr->dwVersion != LEECHRPC_SECURE_VERSION) ||
        (pHdr->cbFrame != (sizeof(LEECHRPC_SECURE_FRAME_HDR) + cbPayload)) ||
        (cbPayload < LEECHRPC_SECURE_TAG_SIZE + sizeof(LEECHRPC_MSG_HDR)) ||
        (pHdr->cbFrame >= 0x10000000) ||
        (pHdr->qwSeq != (pState->qwCryptoSeqRx + 1))) {
        return FALSE;
    }
    cbCipher = cbPayload - LEECHRPC_SECURE_TAG_SIZE;
    if(!(pbPlain = (PBYTE)LocalAlloc(LMEM_FIXED, cbCipher))) {
        return FALSE;
    }
    Http_SecureBuildNonce(pState->rgbCryptoNonceBaseDecrypt, pHdr->qwSeq, rgbNonce);
    BCRYPT_INIT_AUTH_MODE_INFO(AuthInfo);
    AuthInfo.pbNonce = rgbNonce;
    AuthInfo.cbNonce = sizeof(rgbNonce);
    AuthInfo.pbAuthData = (PUCHAR)pHdr;
    AuthInfo.cbAuthData = sizeof(*pHdr);
    AuthInfo.pbTag = pbPayload + cbCipher;
    AuthInfo.cbTag = LEECHRPC_SECURE_TAG_SIZE;
    nt = BCryptDecrypt((BCRYPT_KEY_HANDLE)pState->hCryptoKeyDecrypt, pbPayload, cbCipher, &AuthInfo, NULL, 0, pbPlain, cbCipher, &cbOut, 0);
    SecureZeroMemory(rgbNonce, sizeof(rgbNonce));
    if(!BCRYPT_SUCCESS(nt) || (cbOut != cbCipher)) {
        LocalFree(pbPlain);
        return FALSE;
    }
    pState->qwCryptoSeqRx = pHdr->qwSeq;
    *ppbPlain = pbPlain;
    *pcbPlain = cbCipher;
    return TRUE;
}

static BOOL Http_GetPeerAddress(_In_ SOCKET sClient, _Out_ SOCKADDR_STORAGE *pAddr, _Out_ INT *pcbAddr)
{
    INT cbAddr = sizeof(*pAddr);
    ZeroMemory(pAddr, sizeof(*pAddr));
    if(getpeername(sClient, (SOCKADDR*)pAddr, &cbAddr) == SOCKET_ERROR) {
        return FALSE;
    }
    *pcbAddr = cbAddr;
    return TRUE;
}

static BOOL Http_IsSamePeerAddress(_In_ const SOCKADDR_STORAGE *pAddr1, _In_ INT cbAddr1, _In_ const SOCKADDR_STORAGE *pAddr2, _In_ INT cbAddr2)
{
    UNREFERENCED_PARAMETER(cbAddr1);
    UNREFERENCED_PARAMETER(cbAddr2);
    if(pAddr1->ss_family != pAddr2->ss_family) {
        return FALSE;
    }
    if(pAddr1->ss_family == AF_INET) {
        return ((const struct sockaddr_in*)pAddr1)->sin_addr.s_addr == ((const struct sockaddr_in*)pAddr2)->sin_addr.s_addr;
    }
    if(pAddr1->ss_family == AF_INET6) {
        return 0 == memcmp(&((const struct sockaddr_in6*)pAddr1)->sin6_addr, &((const struct sockaddr_in6*)pAddr2)->sin6_addr, sizeof(((const struct sockaddr_in6*)pAddr1)->sin6_addr));
    }
    return FALSE;
}

static ULONGLONG Http_BootstrapPortMix64(_In_ ULONGLONG value)
{
    value ^= value >> 33;
    value *= 0xff51afd7ed558ccdULL;
    value ^= value >> 33;
    value *= 0xc4ceb9fe1a85ec53ULL;
    value ^= value >> 33;
    return value;
}

static DWORD Http_GetDefaultBootstrapPort()
{
    SYSTEMTIME stUtc = { 0 };
    ULONGLONG seed;
    GetSystemTime(&stUtc);
    seed = ((ULONGLONG)stUtc.wYear << 48)
        | ((ULONGLONG)stUtc.wMonth << 40)
        | ((ULONGLONG)stUtc.wDay << 32)
        | ((ULONGLONG)stUtc.wHour << 24);
    seed = Http_BootstrapPortMix64(seed ^ 0x4b8de0f19c327a61ULL);
    return 30326 + (DWORD)(seed % (40000 - 30326 + 1));
}

static BOOL Http_CreateRedirectListener(_Out_ SOCKET *psListen, _Out_ DWORD *pdwPort)
{
    DWORD i, dwRandom = 0, dwPort = 0;
    DWORD dwBootstrapPort = Http_GetDefaultBootstrapPort();
    SOCKET sListen = INVALID_SOCKET;
    struct sockaddr_in sin = { 0 };
    BOOL opt = TRUE;
    INT cbListenBuf = HTTP_SOCKET_BUFFER_SIZE;
    *psListen = INVALID_SOCKET;
    *pdwPort = 0;
    for(i = 0; i < 128; i++) {
        if(!BCRYPT_SUCCESS(BCryptGenRandom(NULL, (PUCHAR)&dwRandom, sizeof(dwRandom), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
            dwRandom = GetTickCount();
        }
        dwPort = LEECHRPC_REDIRECT_PORT_MIN + (dwRandom % (LEECHRPC_REDIRECT_PORT_MAX - LEECHRPC_REDIRECT_PORT_MIN + 1));
        if(dwPort == dwBootstrapPort) {
            continue;
        }
        sListen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if(sListen == INVALID_SOCKET) {
            continue;
        }
        setsockopt(sListen, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
        setsockopt(sListen, SOL_SOCKET, SO_RCVBUF, (const char*)&cbListenBuf, sizeof(cbListenBuf));
        setsockopt(sListen, SOL_SOCKET, SO_SNDBUF, (const char*)&cbListenBuf, sizeof(cbListenBuf));
        sin.sin_family = AF_INET;
        sin.sin_port = htons((USHORT)dwPort);
        sin.sin_addr.s_addr = INADDR_ANY;
        if((bind(sListen, (struct sockaddr*)&sin, sizeof(sin)) != SOCKET_ERROR) && (listen(sListen, SOMAXCONN) != SOCKET_ERROR)) {
            *psListen = sListen;
            *pdwPort = dwPort;
            return TRUE;
        }
        closesocket(sListen);
        sListen = INVALID_SOCKET;
    }
    return FALSE;
}

static BOOL Http_SendRedirectPortResponse(
    _In_ SOCKET sClient,
    _Inout_ PHTTP_CLIENT_STATE pState,
    _In_ DWORD dwPort,
    _In_reads_bytes_(LEECHRPC_REDIRECT_TOKEN_SIZE) const BYTE *pbToken)
{
    LEECHRPC_MSG_REDIRECT Msg = { 0 };
    Msg.dwMagic = LEECHRPC_MSGMAGIC;
    Msg.cbMsg = sizeof(Msg);
    Msg.tpMsg = LEECHRPC_MSGTYPE_REDIRECT_PORT_RSP;
    Msg.fMsgResult = TRUE;
    Msg.dwPort = dwPort;
    Msg.dwTtlMs = LEECHRPC_SESSION_IDLE_TTL_MS;
    memcpy(Msg.rgbToken, pbToken, sizeof(Msg.rgbToken));
    return Http_SecureSendMessage(sClient, pState, (const BYTE*)&Msg, sizeof(Msg));
}

static BOOL Http_ReceiveRedirectAuth(
    _In_ SOCKET sClient,
    _Inout_ PHTTP_CLIENT_STATE pState,
    _In_ DWORD dwPort,
    _In_reads_bytes_(LEECHRPC_REDIRECT_TOKEN_SIZE) const BYTE *pbToken)
{
    PBYTE pbMsg = NULL;
    DWORD cbMsg = 0;
    PLEECHRPC_MSG_REDIRECT pReq;
    LEECHRPC_MSG_REDIRECT Rsp = { 0 };
    if(!Http_SecureRecvMessage(sClient, pState, &pbMsg, &cbMsg)) {
        return FALSE;
    }
    pReq = (PLEECHRPC_MSG_REDIRECT)pbMsg;
    if((cbMsg != sizeof(LEECHRPC_MSG_REDIRECT)) ||
        (pReq->dwMagic != LEECHRPC_MSGMAGIC) ||
        (pReq->cbMsg != cbMsg) ||
        (pReq->tpMsg != LEECHRPC_MSGTYPE_REDIRECT_AUTH_REQ) ||
        (pReq->dwPort != dwPort) ||
        memcmp(pReq->rgbToken, pbToken, LEECHRPC_REDIRECT_TOKEN_SIZE)) {
        LocalFree(pbMsg);
        return FALSE;
    }
    Rsp.dwMagic = LEECHRPC_MSGMAGIC;
    Rsp.cbMsg = sizeof(Rsp);
    Rsp.tpMsg = LEECHRPC_MSGTYPE_REDIRECT_AUTH_RSP;
    Rsp.fMsgResult = TRUE;
    Rsp.dwPort = dwPort;
    Rsp.dwTtlMs = LEECHRPC_SESSION_IDLE_TTL_MS;
    memcpy(Rsp.rgbToken, pbToken, sizeof(Rsp.rgbToken));
    LocalFree(pbMsg);
    return Http_SecureSendMessage(sClient, pState, (const BYTE*)&Rsp, sizeof(Rsp));
}

static VOID Http_RedirectSessionRelease(_In_opt_ PHTTP_REDIRECT_SESSION pSession)
{
    if(!pSession) { return; }
    if(InterlockedDecrement(&pSession->cRef) == 0) {
        if(pSession->sListen != INVALID_SOCKET) {
            closesocket(pSession->sListen);
            pSession->sListen = INVALID_SOCKET;
        }
        SecureZeroMemory(pSession->rgbToken, sizeof(pSession->rgbToken));
        LocalFree(pSession);
    }
}

static DWORD WINAPI Http_RedirectClientWorker(_In_ LPVOID lpParameter)
{
    PHTTP_REDIRECT_WORKITEM pWork = (PHTTP_REDIRECT_WORKITEM)lpParameter;
    HTTP_CLIENT_STATE State = { 0 };
    BOOL fHandedOff = FALSE;
    Http_ConfigureClientSocket(pWork->sClient);
    pWork->pSession->dwLastActivityTick = GetTickCount();
    if(Http_SecureHandshake(pWork->sClient, &State) &&
        Http_ReceiveRedirectAuth(pWork->sClient, &State, pWork->pSession->dwPort, pWork->pSession->rgbToken)) {
        fHandedOff = Http_HandleClient(pWork->sClient, &State, pWork->pSession);
    }
    if(!fHandedOff) {
        Http_SecureDestroyState(&State);
        LocalFree(State.pbIn);
        shutdown(pWork->sClient, SD_BOTH);
        closesocket(pWork->sClient);
        pWork->pSession->dwLastActivityTick = GetTickCount();
        InterlockedDecrement(&pWork->pSession->cActiveClients);
        Http_RedirectSessionRelease(pWork->pSession);
        InterlockedDecrement(&g_cHttpWorkers);
    }
    LocalFree(pWork);
    return TRUE;
}

static DWORD WINAPI Http_RedirectSessionWorker(_In_ LPVOID lpParameter)
{
    PHTTP_REDIRECT_SESSION pSession = (PHTTP_REDIRECT_SESSION)lpParameter;
    while(!pSession->fStop) {
        fd_set rfds;
        struct timeval tv = { 1, 0 };
        SOCKET sClient = INVALID_SOCKET;
        SOCKADDR_STORAGE Peer = { 0 };
        INT cbPeer = sizeof(Peer);
        if((GetTickCount() - pSession->dwLastActivityTick) > LEECHRPC_SESSION_IDLE_TTL_MS) {
            break;
        }
        FD_ZERO(&rfds);
        FD_SET(pSession->sListen, &rfds);
        if(select(0, &rfds, NULL, NULL, &tv) <= 0) {
            continue;
        }
        sClient = accept(pSession->sListen, (struct sockaddr*)&Peer, &cbPeer);
        if(sClient == INVALID_SOCKET) {
            continue;
        }
        if(!Http_IsSamePeerAddress(&Peer, cbPeer, &pSession->Peer, pSession->cbPeer)) {
            closesocket(sClient);
            continue;
        }
        if(InterlockedIncrement(&g_cHttpWorkers) > HTTP_MAX_WORKERS) {
            InterlockedDecrement(&g_cHttpWorkers);
            closesocket(sClient);
            continue;
        }
        {
            PHTTP_REDIRECT_WORKITEM pWork = (PHTTP_REDIRECT_WORKITEM)LocalAlloc(LMEM_ZEROINIT, sizeof(HTTP_REDIRECT_WORKITEM));
            HANDLE hThread = NULL;
            if(!pWork) {
                InterlockedDecrement(&g_cHttpWorkers);
                closesocket(sClient);
                continue;
            }
            pWork->sClient = sClient;
            pWork->pSession = pSession;
            InterlockedIncrement(&pSession->cRef);
            InterlockedIncrement(&pSession->cActiveClients);
            pSession->dwLastActivityTick = GetTickCount();
            hThread = CreateThread(NULL, 0, Http_RedirectClientWorker, pWork, 0, NULL);
            if(hThread) {
                CloseHandle(hThread);
            } else {
                Http_RedirectClientWorker(pWork);
            }
        }
    }
    if(pSession->sListen != INVALID_SOCKET) {
        shutdown(pSession->sListen, SD_BOTH);
        closesocket(pSession->sListen);
        pSession->sListen = INVALID_SOCKET;
    }
    Http_RedirectSessionRelease(pSession);
    return TRUE;
}

static BOOL Http_CreateRedirectSession(
    _In_ SOCKET sBootstrap,
    _Outptr_ PHTTP_REDIRECT_SESSION *ppSession)
{
    PHTTP_REDIRECT_SESSION pSession = NULL;
    HANDLE hThread = NULL;
    *ppSession = NULL;
    if(!(pSession = (PHTTP_REDIRECT_SESSION)LocalAlloc(LMEM_ZEROINIT, sizeof(HTTP_REDIRECT_SESSION)))) {
        return FALSE;
    }
    pSession->sListen = INVALID_SOCKET;
    pSession->cRef = 2;
    pSession->dwLastActivityTick = GetTickCount();
    if(!Http_GetPeerAddress(sBootstrap, &pSession->Peer, &pSession->cbPeer)) {
        goto fail;
    }
    if(!Http_CreateRedirectListener(&pSession->sListen, &pSession->dwPort)) {
        goto fail;
    }
    if(!BCRYPT_SUCCESS(BCryptGenRandom(NULL, pSession->rgbToken, sizeof(pSession->rgbToken), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        goto fail;
    }
    hThread = CreateThread(NULL, 0, Http_RedirectSessionWorker, pSession, 0, NULL);
    if(!hThread) {
        goto fail;
    }
    CloseHandle(hThread);
    *ppSession = pSession;
    return TRUE;
fail:
    pSession->fStop = TRUE;
    Http_RedirectSessionRelease(pSession);
    Http_RedirectSessionRelease(pSession);
    return FALSE;
}

static BOOL Http_ProcessPlainRequest(_In_reads_bytes_(cbPlain) PBYTE pbPlain, _In_ DWORD cbPlain, _Out_ PBYTE *ppbOut, _Out_ SIZE_T *pcbOut)
{
    PLEECHRPC_MSG_HDR pMsgHdr;
    *ppbOut = NULL;
    *pcbOut = 0;
    if(cbPlain < sizeof(LEECHRPC_MSG_HDR)) {
        return FALSE;
    }
    pMsgHdr = (PLEECHRPC_MSG_HDR)pbPlain;
    if((pMsgHdr->dwMagic != LEECHRPC_MSGMAGIC) || (pMsgHdr->cbMsg != cbPlain) || (pMsgHdr->cbMsg > 0x10000000) || (pMsgHdr->tpMsg > LEECHRPC_MSGTYPE_MAX)) {
        return FALSE;
    }
    LeechGRPC_ReservedSubmitCommand(NULL, pbPlain, cbPlain, ppbOut, pcbOut);
    return *ppbOut && *pcbOut;
}

static BOOL Http_SendEncryptedResponse(_Inout_ PHTTP_CLIENT_CONNECTION pConn, _In_reads_bytes_(cbOut) PBYTE pbOut, _In_ DWORD cbOut)
{
    PHTTP_SEND_ITEM pItem;
    if(pConn->fClosing || pConn->fSendFailed) {
        return FALSE;
    }
    if(!(pItem = (PHTTP_SEND_ITEM)LocalAlloc(LMEM_ZEROINIT, sizeof(HTTP_SEND_ITEM)))) {
        return FALSE;
    }
    pItem->pbOut = pbOut;
    pItem->cbOut = cbOut;
    EnterCriticalSection(&pConn->LockSendQueue);
    if(pConn->pSendTail) {
        pConn->pSendTail->Flink = pItem;
    } else {
        pConn->pSendHead = pItem;
    }
    pConn->pSendTail = pItem;
    InterlockedIncrement(&pConn->cQueuedResponses);
    ResetEvent(pConn->hAllReadScatterDone);
    if(!Http_AsyncKickSendLocked(pConn)) {
        PHTTP_SEND_ITEM pPrev = NULL;
        PHTTP_SEND_ITEM pCur = pConn->pSendHead;
        while(pCur && (pCur != pItem)) {
            pPrev = pCur;
            pCur = pCur->Flink;
        }
        if(pCur == pItem) {
            if(pPrev) {
                pPrev->Flink = pItem->Flink;
            } else {
                pConn->pSendHead = pItem->Flink;
            }
            if(pConn->pSendTail == pItem) {
                pConn->pSendTail = pPrev;
            }
            InterlockedDecrement(&pConn->cQueuedResponses);
            Http_UpdateReadScatterDone(pConn);
        }
        LeaveCriticalSection(&pConn->LockSendQueue);
        if(pItem->pbFrame && !pItem->fFrameEmbeddedInResponse) {
            Http_FramePoolFree(pItem->pbFrame);
        }
        LocalFree(pItem);
        return FALSE;
    }
    LeaveCriticalSection(&pConn->LockSendQueue);
    SetEvent(pConn->hSendEvent);
    return TRUE;
}

static VOID Http_UpdateReadScatterDone(_Inout_ PHTTP_CLIENT_CONNECTION pConn)
{
    if((InterlockedCompareExchange(&pConn->cActiveReadScatter, 0, 0) == 0) &&
        (InterlockedCompareExchange(&pConn->cQueuedResponses, 0, 0) == 0)) {
        SetEvent(pConn->hAllReadScatterDone);
    }
}

static DWORD WINAPI Http_SendThread(_In_ LPVOID lpParameter)
{
    PHTTP_CLIENT_CONNECTION pConn = (PHTTP_CLIENT_CONNECTION)lpParameter;
    while(TRUE) {
        DWORD dwWait = WaitForSingleObject(pConn->hSendEvent, 1000);
        if(dwWait == WAIT_TIMEOUT) {
            if(Http_ConnIsIdleTimedOut(pConn)) {
                Http_ConnClose(pConn);
                break;
            }
            continue;
        }
        if(dwWait != WAIT_OBJECT_0) {
            Http_ConnClose(pConn);
            break;
        }
        EnterCriticalSection(&pConn->LockSendQueue);
        if(!pConn->pSendHead) {
            ResetEvent(pConn->hSendEvent);
        } else if(!Http_AsyncKickSendLocked(pConn)) {
            LeaveCriticalSection(&pConn->LockSendQueue);
            Http_ConnClose(pConn);
            break;
        }
        LeaveCriticalSection(&pConn->LockSendQueue);
        if(pConn->fStopSendThread && !pConn->pSendHead && !pConn->fSendInFlight) {
            break;
        }
    }
    Http_ConnRelease(pConn);
    return 0;
}

static VOID Http_ReadScatterTaskComplete(_Inout_ PHTTP_READSCATTER_TASK pTask)
{
    PBYTE pbOut = NULL;
    SIZE_T cbOut = 0;
        if(Http_ProcessPlainRequest(pTask->pbPlain, pTask->cbPlain, &pbOut, &cbOut)) {
            if(!Http_SendEncryptedResponse(pTask->pConn, pbOut, (DWORD)cbOut)) {
            LeechRpc_ServerResponseFree(pbOut);
        } else {
            pbOut = NULL;
        }
    }
    LeechRpc_ServerResponseFree(pbOut);
    LocalFree(pTask->pbPlain);
    InterlockedDecrement(&pTask->pConn->cActiveReadScatter);
    Http_UpdateReadScatterDone(pTask->pConn);
    ReleaseSemaphore(pTask->pConn->hReadScatterSlots, 1, NULL);
    Http_ConnRelease(pTask->pConn);
}

static DWORD WINAPI Http_ReadScatterWorker(_In_ LPVOID lpParameter)
{
    PHTTP_READSCATTER_TASK pTask = (PHTTP_READSCATTER_TASK)lpParameter;
    UNREFERENCED_PARAMETER(lpParameter);
    while(TRUE) {
        if(!pTask) {
            WaitForSingleObject(g_hHttpReadScatterQueueSem, INFINITE);
            EnterCriticalSection(&g_HttpReadScatterQueueLock);
            pTask = g_pHttpReadScatterQueueHead;
            if(pTask) {
                g_pHttpReadScatterQueueHead = pTask->Flink;
                if(!g_pHttpReadScatterQueueHead) {
                    g_pHttpReadScatterQueueTail = NULL;
                }
                pTask->Flink = NULL;
            }
            LeaveCriticalSection(&g_HttpReadScatterQueueLock);
            if(!pTask) {
                if(g_fHttpReadScatterWorkersStop) {
                    break;
                }
                continue;
            }
        }
        Http_ReadScatterTaskComplete(pTask);
        LocalFree(pTask);
        pTask = NULL;
    }
    return 0;
}

static BOOL Http_QueueReadScatterTask(_Inout_ PHTTP_READSCATTER_TASK pTask)
{
    EnterCriticalSection(&g_HttpReadScatterQueueLock);
    pTask->Flink = NULL;
    if(g_pHttpReadScatterQueueTail) {
        g_pHttpReadScatterQueueTail->Flink = pTask;
    } else {
        g_pHttpReadScatterQueueHead = pTask;
    }
    g_pHttpReadScatterQueueTail = pTask;
    LeaveCriticalSection(&g_HttpReadScatterQueueLock);
    return ReleaseSemaphore(g_hHttpReadScatterQueueSem, 1, NULL) ? TRUE : FALSE;
}

static BOOL Http_ReadScatterWorkersStart()
{
    DWORD i;
    if(InterlockedCompareExchange(&g_fHttpReadScatterWorkersInitialized, TRUE, FALSE)) {
        return TRUE;
    }
    InitializeCriticalSection(&g_HttpReadScatterQueueLock);
    g_hHttpReadScatterQueueSem = CreateSemaphore(NULL, 0, 0x7fffffff, NULL);
    if(!g_hHttpReadScatterQueueSem) {
        DeleteCriticalSection(&g_HttpReadScatterQueueLock);
        InterlockedExchange(&g_fHttpReadScatterWorkersInitialized, FALSE);
        return FALSE;
    }
    g_fHttpReadScatterWorkersStop = FALSE;
    for(i = 0; i < HTTP_READSCATTER_WORKERS; i++) {
        g_ahHttpReadScatterWorkers[i] = CreateThread(NULL, 0, Http_ReadScatterWorker, NULL, 0, NULL);
        if(!g_ahHttpReadScatterWorkers[i]) {
            g_fHttpReadScatterWorkersStop = TRUE;
            while(i--) {
                ReleaseSemaphore(g_hHttpReadScatterQueueSem, 1, NULL);
                WaitForSingleObject(g_ahHttpReadScatterWorkers[i], 2000);
                CloseHandle(g_ahHttpReadScatterWorkers[i]);
                g_ahHttpReadScatterWorkers[i] = NULL;
            }
            CloseHandle(g_hHttpReadScatterQueueSem);
            g_hHttpReadScatterQueueSem = NULL;
            DeleteCriticalSection(&g_HttpReadScatterQueueLock);
            InterlockedExchange(&g_fHttpReadScatterWorkersInitialized, FALSE);
            return FALSE;
        }
    }
    return TRUE;
}

static VOID Http_ReadScatterWorkersStop()
{
    DWORD i;
    PHTTP_READSCATTER_TASK pTask;
    if(!InterlockedCompareExchange(&g_fHttpReadScatterWorkersInitialized, TRUE, TRUE)) {
        return;
    }
    g_fHttpReadScatterWorkersStop = TRUE;
    for(i = 0; i < HTTP_READSCATTER_WORKERS; i++) {
        ReleaseSemaphore(g_hHttpReadScatterQueueSem, 1, NULL);
    }
    for(i = 0; i < HTTP_READSCATTER_WORKERS; i++) {
        if(g_ahHttpReadScatterWorkers[i]) {
            WaitForSingleObject(g_ahHttpReadScatterWorkers[i], 5000);
            CloseHandle(g_ahHttpReadScatterWorkers[i]);
            g_ahHttpReadScatterWorkers[i] = NULL;
        }
    }
    EnterCriticalSection(&g_HttpReadScatterQueueLock);
    pTask = g_pHttpReadScatterQueueHead;
    g_pHttpReadScatterQueueHead = NULL;
    g_pHttpReadScatterQueueTail = NULL;
    LeaveCriticalSection(&g_HttpReadScatterQueueLock);
    while(pTask) {
        PHTTP_READSCATTER_TASK pNext = pTask->Flink;
        LocalFree(pTask->pbPlain);
        LocalFree(pTask);
        pTask = pNext;
    }
    if(g_hHttpReadScatterQueueSem) {
        CloseHandle(g_hHttpReadScatterQueueSem);
        g_hHttpReadScatterQueueSem = NULL;
    }
    DeleteCriticalSection(&g_HttpReadScatterQueueLock);
    InterlockedExchange(&g_fHttpReadScatterWorkersInitialized, FALSE);
}

static VOID Http_ConnAddRef(_Inout_ PHTTP_CLIENT_CONNECTION pConn)
{
    InterlockedIncrement(&pConn->cRef);
}

static VOID Http_ConnClose(_Inout_ PHTTP_CLIENT_CONNECTION pConn)
{
    if(InterlockedExchange(&pConn->fClosing, TRUE)) {
        return;
    }
    if(pConn->sClient != INVALID_SOCKET) {
        shutdown(pConn->sClient, SD_BOTH);
        closesocket(pConn->sClient);
        pConn->sClient = INVALID_SOCKET;
    }
    pConn->fStopSendThread = TRUE;
    if(pConn->hSendEvent) {
        SetEvent(pConn->hSendEvent);
    }
}

static VOID Http_ConnRelease(_Inout_ PHTTP_CLIENT_CONNECTION pConn)
{
    if(InterlockedDecrement(&pConn->cRef) == 0) {
        DWORD dwCurrentThreadId = GetCurrentThreadId();
        PHTTP_SEND_ITEM pItem;
        Http_ConnClose(pConn);
        if(pConn->hSendThread) {
            if((pConn->dwSendThreadId != dwCurrentThreadId) && (WaitForSingleObject(pConn->hSendThread, 5000) == WAIT_OBJECT_0)) {
                /* sender drained */
            }
            CloseHandle(pConn->hSendThread);
            pConn->hSendThread = NULL;
        }
        if(pConn->hSendEvent) {
            CloseHandle(pConn->hSendEvent);
            pConn->hSendEvent = NULL;
        }
        if(pConn->hReadScatterSlots) {
            CloseHandle(pConn->hReadScatterSlots);
            pConn->hReadScatterSlots = NULL;
        }
        if(pConn->hAllReadScatterDone) {
            CloseHandle(pConn->hAllReadScatterDone);
            pConn->hAllReadScatterDone = NULL;
        }
        while((pItem = pConn->pSendHead)) {
            pConn->pSendHead = pItem->Flink;
            if(pItem->pbFrame && !pItem->fFrameEmbeddedInResponse) {
                Http_FramePoolFree(pItem->pbFrame);
            }
            LeechRpc_ServerResponseFree(pItem->pbOut);
            LocalFree(pItem);
        }
        if(pConn->pRecvOp) {
            if(pConn->pRecvOp->pbPayload) {
                LocalFree(pConn->pRecvOp->pbPayload);
                pConn->pRecvOp->pbPayload = NULL;
            }
            LocalFree(pConn->pRecvOp);
            pConn->pRecvOp = NULL;
        }
        DeleteCriticalSection(&pConn->LockSendQueue);
        Http_SecureDestroyState(&pConn->State);
        LocalFree(pConn->State.pbIn);
        if(pConn->pSession) {
            pConn->pSession->dwLastActivityTick = GetTickCount();
            InterlockedDecrement(&pConn->pSession->cActiveClients);
            Http_RedirectSessionRelease(pConn->pSession);
            pConn->pSession = NULL;
        }
        InterlockedDecrement(&g_cHttpWorkers);
        LocalFree(pConn);
    }
}

static BOOL Http_ConnIsIdleTimedOut(_In_ PHTTP_CLIENT_CONNECTION pConn)
{
    if(pConn->fClosing) {
        return TRUE;
    }
    if(InterlockedCompareExchange(&pConn->cActiveReadScatter, 0, 0) != 0) {
        return FALSE;
    }
    if(InterlockedCompareExchange(&pConn->cQueuedResponses, 0, 0) != 0) {
        return FALSE;
    }
    return (GetTickCount() - pConn->dwLastActivityTick) > HTTP_CLIENT_IDLE_TIMEOUT_MS;
}

static BOOL Http_AsyncKickSendLocked(_Inout_ PHTTP_CLIENT_CONNECTION pConn)
{
    DWORD cbSent = 0;
    PHTTP_SEND_ITEM pItem;
    DWORD cBuffers = 0;
    int wsaResult;
    if(pConn->fClosing || pConn->fSendFailed || (pConn->sClient == INVALID_SOCKET)) {
        return FALSE;
    }
    if(InterlockedCompareExchange(&pConn->fSendInFlight, TRUE, FALSE)) {
        return TRUE;
    }
    pItem = pConn->pSendHead;
    if(!pItem) {
        InterlockedExchange(&pConn->fSendInFlight, FALSE);
        return TRUE;
    }
    ZeroMemory(&pConn->SendOp, sizeof(pConn->SendOp));
    pConn->SendOp.dwOpType = HTTP_ASYNC_IO_OP_SEND;
    pConn->SendOp.pConn = pConn;
    while(pItem && (cBuffers < HTTP_ASYNC_SEND_BURST_MAX)) {
        if(!pItem->pbFrame) {
            if(!Http_SecureBuildMessageFrame(&pConn->State, pItem->pbOut, pItem->cbOut, &pItem->pbFrame, &pItem->cbFrame)) {
                InterlockedExchange(&pConn->fSendInFlight, FALSE);
                return FALSE;
            }
            pItem->fFrameEmbeddedInResponse = (pItem->pbFrame + sizeof(LEECHRPC_SECURE_FRAME_HDR) == pItem->pbOut);
            pItem->cbSent = 0;
        }
        if(pItem->cbSent >= pItem->cbFrame) {
            InterlockedExchange(&pConn->fSendInFlight, FALSE);
            return FALSE;
        }
        pConn->SendOp.WsaBuf[cBuffers].buf = (CHAR*)pItem->pbFrame + pItem->cbSent;
        pConn->SendOp.WsaBuf[cBuffers].len = pItem->cbFrame - pItem->cbSent;
        cBuffers++;
        pItem = pItem->Flink;
    }
    if(!cBuffers) {
        InterlockedExchange(&pConn->fSendInFlight, FALSE);
        return TRUE;
    }
    pConn->SendOp.cBuffers = cBuffers;
    Http_ConnAddRef(pConn);
    wsaResult = WSASend(pConn->sClient, pConn->SendOp.WsaBuf, pConn->SendOp.cBuffers, &cbSent, 0, &pConn->SendOp.Ov, NULL);
    if((wsaResult == SOCKET_ERROR) && (WSAGetLastError() != WSA_IO_PENDING)) {
        Http_ConnRelease(pConn);
        InterlockedExchange(&pConn->fSendInFlight, FALSE);
        return FALSE;
    }
    return TRUE;
}

static BOOL Http_DispatchPlainMessage(_Inout_ PHTTP_CLIENT_CONNECTION pConn, _In_reads_bytes_(cbPlain) PBYTE pbPlain, _In_ DWORD cbPlain)
{
    PBYTE pbOut = NULL;
    SIZE_T cbOut = 0;
    PLEECHRPC_MSG_HDR pMsgHdr = (PLEECHRPC_MSG_HDR)pbPlain;
    if((cbPlain < sizeof(LEECHRPC_MSG_HDR)) ||
        (pMsgHdr->dwMagic != LEECHRPC_MSGMAGIC) ||
        (pMsgHdr->cbMsg != cbPlain) ||
        (pMsgHdr->cbMsg > 0x10000000) ||
        (pMsgHdr->tpMsg > LEECHRPC_MSGTYPE_MAX) ||
        pConn->fSendFailed) {
        return FALSE;
    }
    if(pMsgHdr->tpMsg == LEECHRPC_MSGTYPE_READSCATTER_REQ) {
        PHTTP_READSCATTER_TASK pTask;
        WaitForSingleObject(pConn->hReadScatterSlots, INFINITE);
        if(!(pTask = (PHTTP_READSCATTER_TASK)LocalAlloc(LMEM_ZEROINIT, sizeof(HTTP_READSCATTER_TASK)))) {
            ReleaseSemaphore(pConn->hReadScatterSlots, 1, NULL);
            return FALSE;
        }
        ResetEvent(pConn->hAllReadScatterDone);
        InterlockedIncrement(&pConn->cActiveReadScatter);
        Http_ConnAddRef(pConn);
        pTask->pConn = pConn;
        pTask->pbPlain = pbPlain;
        pTask->cbPlain = cbPlain;
        if(!Http_QueueReadScatterTask(pTask)) {
            InterlockedDecrement(&pConn->cActiveReadScatter);
            ReleaseSemaphore(pConn->hReadScatterSlots, 1, NULL);
            Http_ConnRelease(pConn);
            LocalFree(pTask->pbPlain);
            LocalFree(pTask);
            return FALSE;
        }
        return TRUE;
    }
    if(!Http_ProcessPlainRequest(pbPlain, cbPlain, &pbOut, &cbOut) ||
        !Http_SendEncryptedResponse(pConn, pbOut, (DWORD)cbOut)) {
        LeechRpc_ServerResponseFree(pbOut);
        return FALSE;
    }
    return TRUE;
}

static BOOL Http_AsyncPostRecv(_Inout_ PHTTP_CLIENT_CONNECTION pConn)
{
    DWORD dwFlags = 0;
    DWORD cbRecv = 0;
    WSABUF WsaBuf;
    PHTTP_ASYNC_RECV_OP pOp = pConn->pRecvOp;
    int wsaResult;
    if(!pOp || pConn->fClosing || (pConn->sClient == INVALID_SOCKET)) {
        return FALSE;
    }
    WsaBuf.buf = pOp->fRecvHeader ? (CHAR*)pOp->rgbHdr + pOp->cbReceived : (CHAR*)pOp->pbPayload + pOp->cbReceived;
    WsaBuf.len = pOp->cbExpected - pOp->cbReceived;
    ZeroMemory(&pOp->Ov, sizeof(pOp->Ov));
    Http_ConnAddRef(pConn);
    wsaResult = WSARecv(pConn->sClient, &WsaBuf, 1, &cbRecv, &dwFlags, &pOp->Ov, NULL);
    if((wsaResult == SOCKET_ERROR) && (WSAGetLastError() != WSA_IO_PENDING)) {
        Http_ConnRelease(pConn);
        return FALSE;
    }
    return TRUE;
}

static DWORD WINAPI Http_AsyncIoWorker(_In_ LPVOID lpParameter)
{
    HANDLE hIocp = (HANDLE)lpParameter;
    while(TRUE) {
        DWORD cbTransferred = 0;
        ULONG_PTR ulKey = 0;
        LPOVERLAPPED pOv = NULL;
        PHTTP_ASYNC_IO_COMMON pCommon;
        PHTTP_ASYNC_RECV_OP pOp;
        PHTTP_CLIENT_CONNECTION pConn;
        PBYTE pbPlain = NULL;
        DWORD cbPlain = 0;
        if(!GetQueuedCompletionStatus(hIocp, &cbTransferred, &ulKey, &pOv, INFINITE)) {
            if(!pOv) {
                if(g_fHttpAsyncIoStop) { break; }
                continue;
            }
        }
        if(!pOv) {
            if(g_fHttpAsyncIoStop) { break; }
            continue;
        }
        pCommon = CONTAINING_RECORD(pOv, HTTP_ASYNC_IO_COMMON, Ov);
        pConn = pCommon->pConn;
        if(!pConn) { continue; }
        if(pCommon->dwOpType == HTTP_ASYNC_IO_OP_SEND) {
            PHTTP_SEND_ITEM pItem = NULL;
            DWORD cbRemaining = cbTransferred;
            BOOL fStartNext = FALSE;
            if((cbTransferred == 0) || pConn->fClosing) {
                Http_ConnClose(pConn);
                Http_ConnRelease(pConn);
                continue;
            }
            pConn->dwLastActivityTick = GetTickCount();
            EnterCriticalSection(&pConn->LockSendQueue);
            pItem = pConn->pSendHead;
            if(!pItem) {
                InterlockedExchange(&pConn->fSendInFlight, FALSE);
                ResetEvent(pConn->hSendEvent);
                LeaveCriticalSection(&pConn->LockSendQueue);
                Http_ConnRelease(pConn);
                continue;
            }
            while(pItem && cbRemaining) {
                DWORD cbLeftItem = pItem->cbFrame - pItem->cbSent;
                DWORD cbConsume = min(cbRemaining, cbLeftItem);
                pItem->cbSent += cbConsume;
                cbRemaining -= cbConsume;
                if(pItem->cbSent >= pItem->cbFrame) {
                    PHTTP_SEND_ITEM pDone = pItem;
                    pConn->pSendHead = pItem->Flink;
                    pItem = pConn->pSendHead;
                    if(!pConn->pSendHead) {
                        pConn->pSendTail = NULL;
                        ResetEvent(pConn->hSendEvent);
                    } else {
                        fStartNext = TRUE;
                    }
                    InterlockedDecrement(&pConn->cQueuedResponses);
                    Http_UpdateReadScatterDone(pConn);
                    if(pDone->pbFrame && !pDone->fFrameEmbeddedInResponse) {
                        Http_FramePoolFree(pDone->pbFrame);
                    }
                    LeechRpc_ServerResponseFree(pDone->pbOut);
                    LocalFree(pDone);
                } else {
                    fStartNext = TRUE;
                    break;
                }
            }
            InterlockedExchange(&pConn->fSendInFlight, FALSE);
            if(fStartNext && !Http_AsyncKickSendLocked(pConn)) {
                LeaveCriticalSection(&pConn->LockSendQueue);
                Http_ConnClose(pConn);
                Http_ConnRelease(pConn);
                continue;
            }
            LeaveCriticalSection(&pConn->LockSendQueue);
            Http_ConnRelease(pConn);
            continue;
        }
        pOp = (PHTTP_ASYNC_RECV_OP)pCommon;
        if((cbTransferred == 0) || pConn->fClosing) {
            Http_ConnClose(pConn);
            Http_ConnRelease(pConn);
            continue;
        }
        pConn->dwLastActivityTick = GetTickCount();
        pOp->cbReceived += cbTransferred;
        if(pOp->cbReceived < pOp->cbExpected) {
            if(!Http_AsyncPostRecv(pConn)) {
                Http_ConnClose(pConn);
            }
            Http_ConnRelease(pConn);
            continue;
        }
        if(pOp->fRecvHeader) {
            memcpy(&pOp->Hdr, pOp->rgbHdr, sizeof(pOp->Hdr));
            if((pOp->Hdr.dwMagic != LEECHRPC_SECURE_FRAME_MAGIC) ||
                (pOp->Hdr.dwVersion != LEECHRPC_SECURE_VERSION) ||
                (pOp->Hdr.cbFrame < sizeof(LEECHRPC_SECURE_FRAME_HDR) + LEECHRPC_SECURE_TAG_SIZE + sizeof(LEECHRPC_MSG_HDR)) ||
                (pOp->Hdr.cbFrame >= 0x10000000)) {
                Http_ConnClose(pConn);
                Http_ConnRelease(pConn);
                continue;
            }
            pOp->cbExpected = pOp->Hdr.cbFrame - sizeof(LEECHRPC_SECURE_FRAME_HDR);
            pOp->cbReceived = 0;
            pOp->fRecvHeader = FALSE;
            if(pOp->cbPayloadAlloc < pOp->cbExpected) {
                PBYTE pbNew = (PBYTE)LocalAlloc(LMEM_FIXED, pOp->cbExpected);
                if(!pbNew) {
                    Http_ConnClose(pConn);
                    Http_ConnRelease(pConn);
                    continue;
                }
                LocalFree(pOp->pbPayload);
                pOp->pbPayload = pbNew;
                pOp->cbPayloadAlloc = pOp->cbExpected;
            }
            if(!Http_AsyncPostRecv(pConn)) {
                Http_ConnClose(pConn);
            }
            Http_ConnRelease(pConn);
            continue;
        }
        {
            BOOL fReadScatterPlain = FALSE;
            if(!Http_SecureDecryptReceivedMessage(&pConn->State, &pOp->Hdr, pOp->pbPayload, pOp->cbExpected, &pbPlain, &cbPlain)) {
                LocalFree(pbPlain);
                Http_ConnClose(pConn);
                Http_ConnRelease(pConn);
                continue;
            }
            if(cbPlain >= sizeof(LEECHRPC_MSG_HDR)) {
                fReadScatterPlain = (((PLEECHRPC_MSG_HDR)pbPlain)->tpMsg == LEECHRPC_MSGTYPE_READSCATTER_REQ);
            }
            if(!Http_DispatchPlainMessage(pConn, pbPlain, cbPlain)) {
                LocalFree(pbPlain);
                Http_ConnClose(pConn);
                Http_ConnRelease(pConn);
                continue;
            }
            if(!fReadScatterPlain) {
                LocalFree(pbPlain);
            }
        }
        pOp->fRecvHeader = TRUE;
        pOp->cbExpected = sizeof(LEECHRPC_SECURE_FRAME_HDR);
        pOp->cbReceived = 0;
        if(!Http_AsyncPostRecv(pConn)) {
            Http_ConnClose(pConn);
        }
        Http_ConnRelease(pConn);
    }
    return 0;
}

static BOOL Http_AsyncIoStart()
{
    DWORD i;
    if(InterlockedCompareExchange(&g_fHttpAsyncIoInitialized, TRUE, FALSE)) {
        return TRUE;
    }
    if(!InterlockedCompareExchange(&g_fHttpFramePoolInitialized, TRUE, FALSE)) {
        InitializeCriticalSection(&g_HttpFramePoolLock);
    }
    g_fHttpAsyncIoStop = FALSE;
    g_hHttpAsyncIoCp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if(!g_hHttpAsyncIoCp) {
        InterlockedExchange(&g_fHttpAsyncIoInitialized, FALSE);
        return FALSE;
    }
    for(i = 0; i < HTTP_ASYNC_IO_WORKERS; i++) {
        g_ahHttpAsyncIoWorkers[i] = CreateThread(NULL, 0, Http_AsyncIoWorker, g_hHttpAsyncIoCp, 0, NULL);
        if(!g_ahHttpAsyncIoWorkers[i]) {
            g_fHttpAsyncIoStop = TRUE;
            while(i--) {
                PostQueuedCompletionStatus(g_hHttpAsyncIoCp, 0, 0, NULL);
                WaitForSingleObject(g_ahHttpAsyncIoWorkers[i], 2000);
                CloseHandle(g_ahHttpAsyncIoWorkers[i]);
                g_ahHttpAsyncIoWorkers[i] = NULL;
            }
            CloseHandle(g_hHttpAsyncIoCp);
            g_hHttpAsyncIoCp = NULL;
            InterlockedExchange(&g_fHttpAsyncIoInitialized, FALSE);
            return FALSE;
        }
    }
    return TRUE;
}

static VOID Http_AsyncIoStop()
{
    DWORD i;
    if(!InterlockedCompareExchange(&g_fHttpAsyncIoInitialized, TRUE, TRUE)) {
        return;
    }
    g_fHttpAsyncIoStop = TRUE;
    for(i = 0; i < HTTP_ASYNC_IO_WORKERS; i++) {
        PostQueuedCompletionStatus(g_hHttpAsyncIoCp, 0, 0, NULL);
    }
    for(i = 0; i < HTTP_ASYNC_IO_WORKERS; i++) {
        if(g_ahHttpAsyncIoWorkers[i]) {
            WaitForSingleObject(g_ahHttpAsyncIoWorkers[i], 5000);
            CloseHandle(g_ahHttpAsyncIoWorkers[i]);
            g_ahHttpAsyncIoWorkers[i] = NULL;
        }
    }
    if(g_hHttpAsyncIoCp) {
        CloseHandle(g_hHttpAsyncIoCp);
        g_hHttpAsyncIoCp = NULL;
    }
    InterlockedExchange(&g_fHttpAsyncIoInitialized, FALSE);
    if(InterlockedCompareExchange(&g_fHttpFramePoolInitialized, FALSE, TRUE)) {
        for(i = 0; i < HTTP_FRAMEPOOL_BUCKETS; i++) {
            while(g_HttpFramePoolHead[i]) {
                PHTTP_FRAME_POOL_HDR pHdr = g_HttpFramePoolHead[i];
                g_HttpFramePoolHead[i] = pHdr->Flink;
                LocalFree(pHdr);
            }
            g_cHttpFramePoolCount[i] = 0;
        }
        DeleteCriticalSection(&g_HttpFramePoolLock);
    }
}

static BOOL Http_HandleClient(_In_ SOCKET sClient, _Inout_ PHTTP_CLIENT_STATE pState, _In_ PHTTP_REDIRECT_SESSION pSession)
{
    PHTTP_CLIENT_CONNECTION pConn = NULL;
    PHTTP_ASYNC_RECV_OP pRecvOp = NULL;
    if(!g_hHttpAsyncIoCp) {
        return FALSE;
    }
    if(!(pConn = (PHTTP_CLIENT_CONNECTION)LocalAlloc(LMEM_ZEROINIT, sizeof(HTTP_CLIENT_CONNECTION)))) {
        return FALSE;
    }
    if(!(pRecvOp = (PHTTP_ASYNC_RECV_OP)LocalAlloc(LMEM_ZEROINIT, sizeof(HTTP_ASYNC_RECV_OP)))) {
        LocalFree(pConn);
        return FALSE;
    }
    pConn->sClient = sClient;
    pConn->pSession = pSession;
    pConn->State = *pState;
    ZeroMemory(pState, sizeof(*pState));
    pConn->pRecvOp = pRecvOp;
    pRecvOp->pConn = pConn;
    pRecvOp->dwOpType = HTTP_ASYNC_IO_OP_RECV;
    pRecvOp->fRecvHeader = TRUE;
    pRecvOp->cbExpected = sizeof(LEECHRPC_SECURE_FRAME_HDR);
    pRecvOp->cbReceived = 0;
    pConn->cRef = 1;
    pConn->dwLastActivityTick = GetTickCount();
    InitializeCriticalSection(&pConn->LockSendQueue);
    pConn->hSendEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    pConn->hReadScatterSlots = CreateSemaphore(NULL, HTTP_READMUX_MAX_INFLIGHT, HTTP_READMUX_MAX_INFLIGHT, NULL);
    pConn->hAllReadScatterDone = CreateEvent(NULL, TRUE, TRUE, NULL);
    if(!pConn->hSendEvent || !pConn->hReadScatterSlots || !pConn->hAllReadScatterDone) {
        Http_ConnRelease(pConn);
        return FALSE;
    }
    Http_ConnAddRef(pConn);
    pConn->hSendThread = CreateThread(NULL, 0, Http_SendThread, pConn, 0, &pConn->dwSendThreadId);
    if(!pConn->hSendThread) {
        Http_ConnRelease(pConn);
        Http_ConnRelease(pConn);
        return FALSE;
    }
    if(!CreateIoCompletionPort((HANDLE)pConn->sClient, g_hHttpAsyncIoCp, 0, 0)) {
        Http_ConnClose(pConn);
        Http_ConnRelease(pConn);
        return FALSE;
    }
    if(!Http_AsyncPostRecv(pConn)) {
        Http_ConnClose(pConn);
        Http_ConnRelease(pConn);
        return FALSE;
    }
    Http_ConnRelease(pConn);
    return TRUE;
}

static VOID Http_ConfigureClientSocket(_In_ SOCKET sClient)
{
    DWORD dwTimeoutMs = 15000;
    BOOL fTcpNoDelay = TRUE;
    BOOL fKeepAlive = TRUE;
    INT cbSockBuf = HTTP_SOCKET_BUFFER_SIZE;
    setsockopt(sClient, IPPROTO_TCP, TCP_NODELAY, (const char*)&fTcpNoDelay, sizeof(fTcpNoDelay));
    setsockopt(sClient, SOL_SOCKET, SO_KEEPALIVE, (const char*)&fKeepAlive, sizeof(fKeepAlive));
    setsockopt(sClient, SOL_SOCKET, SO_RCVTIMEO, (const char*)&dwTimeoutMs, sizeof(dwTimeoutMs));
    setsockopt(sClient, SOL_SOCKET, SO_SNDTIMEO, (const char*)&dwTimeoutMs, sizeof(dwTimeoutMs));
    setsockopt(sClient, SOL_SOCKET, SO_RCVBUF, (const char*)&cbSockBuf, sizeof(cbSockBuf));
    setsockopt(sClient, SOL_SOCKET, SO_SNDBUF, (const char*)&cbSockBuf, sizeof(cbSockBuf));
}

static DWORD WINAPI Http_ClientWorker(_In_ LPVOID lpParameter)
{
    SOCKET sBootstrap = (SOCKET)(ULONG_PTR)lpParameter;
    HTTP_CLIENT_STATE State = { 0 };
    PHTTP_REDIRECT_SESSION pSession = NULL;
    Http_ConfigureClientSocket(sBootstrap);
    if(Http_SecureHandshake(sBootstrap, &State)) {
        if(Http_CreateRedirectSession(sBootstrap, &pSession)) {
            if(!Http_SendRedirectPortResponse(sBootstrap, &State, pSession->dwPort, pSession->rgbToken)) {
                pSession->fStop = TRUE;
                if(pSession->sListen != INVALID_SOCKET) {
                    shutdown(pSession->sListen, SD_BOTH);
                    closesocket(pSession->sListen);
                    pSession->sListen = INVALID_SOCKET;
                }
            }
            Http_RedirectSessionRelease(pSession);
        }
    }
    Http_SecureDestroyState(&State);
    LocalFree(State.pbIn);
    if(sBootstrap != INVALID_SOCKET) {
        shutdown(sBootstrap, SD_BOTH);
        closesocket(sBootstrap);
    }
    InterlockedDecrement(&g_cHttpWorkers);
    return TRUE;
}

_Success_(return)
BOOL HttpServeLoop(_In_ PLEECHSVC_CONFIG pConfig, _In_opt_ HANDLE hStopEvent)
{
    WSADATA wsa = { 0 };
    SOCKET sListen = INVALID_SOCKET, sClient = INVALID_SOCKET;
    HANDLE hThread = NULL;
    BOOL fResult = FALSE;
    DWORD i;
    USHORT uPort = (USHORT)_wtoi(pConfig->wszTcpPortHTTP);
    if(!uPort || (uPort == (USHORT)_wtoi(LEECHSVC_TCP_PORT_HTTP))) {
        uPort = (USHORT)Http_GetDefaultBootstrapPort();
    }
    if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { return FALSE; }
    if(!Http_ReadScatterWorkersStart()) { goto cleanup; }
    if(!Http_AsyncIoStart()) { goto cleanup; }
    sListen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sListen == INVALID_SOCKET) { goto cleanup; }
    {
        BOOL opt = TRUE;
        INT cbListenBuf = HTTP_SOCKET_BUFFER_SIZE;
        setsockopt(sListen, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
        setsockopt(sListen, SOL_SOCKET, SO_RCVBUF, (const char*)&cbListenBuf, sizeof(cbListenBuf));
        setsockopt(sListen, SOL_SOCKET, SO_SNDBUF, (const char*)&cbListenBuf, sizeof(cbListenBuf));
    }
    struct sockaddr_in sin = { 0 };
    sin.sin_family = AF_INET;
    sin.sin_port = htons(uPort);
    sin.sin_addr.s_addr = INADDR_ANY;
    if(bind(sListen, (struct sockaddr*)&sin, sizeof(sin)) == SOCKET_ERROR) { goto cleanup; }
    if(listen(sListen, SOMAXCONN) == SOCKET_ERROR) { goto cleanup; }
    printf("LeechAgent TCP message transport listening on tcp/%hu ...\n", uPort);
    while(TRUE) {
        fd_set rfds;
        struct timeval tv = { 1, 0 };
        FD_ZERO(&rfds);
        FD_SET(sListen, &rfds);
        int r = select(0, &rfds, NULL, NULL, &tv);
        if(r > 0 && FD_ISSET(sListen, &rfds)) {
            sClient = accept(sListen, NULL, NULL);
            if(sClient != INVALID_SOCKET) {
                if(InterlockedIncrement(&g_cHttpWorkers) > HTTP_MAX_WORKERS) {
                    InterlockedDecrement(&g_cHttpWorkers);
                    closesocket(sClient);
                    sClient = INVALID_SOCKET;
                    continue;
                }
                hThread = CreateThread(NULL, 0, Http_ClientWorker, (LPVOID)(ULONG_PTR)sClient, 0, NULL);
                if(hThread) {
                    CloseHandle(hThread);
                } else {
                    Http_ClientWorker((LPVOID)(ULONG_PTR)sClient);
                }
                sClient = INVALID_SOCKET;
            }
        }
        if(hStopEvent && (WaitForSingleObject(hStopEvent, 0) == WAIT_OBJECT_0)) { break; }
    }
    fResult = TRUE;
cleanup:
    if(sListen != INVALID_SOCKET) { closesocket(sListen); }
    for(i = 0; i < 500; i++) {
        if(InterlockedCompareExchange(&g_cHttpWorkers, 0, 0) == 0) { break; }
        Sleep(10);
    }
    Http_AsyncIoStop();
    Http_ReadScatterWorkersStop();
    WSACleanup();
    return fResult;
}
_Success_(return)
BOOL RpcStartGRPC(_In_ PLEECHSVC_CONFIG pConfig)
{
    DWORD dwTcpPort = 0;
    if(!pConfig->hModuleGRPC) {
        printf("Failed: gRPC: library 'leechgrpc.dll' missing - gRPC functionality is disabled.\n");
        return FALSE;
    }
    dwTcpPort = _wtoi(pConfig->wszTcpPortGRPC);
    if(!dwTcpPort) {
        printf("Failed: gRPC: Invalid port number '%i' - gRPC functionality is disabled.\n", dwTcpPort);
        return FALSE;
    }
    g_pfn_leechgrpc_server_create_insecure = (pfn_leechgrpc_server_create_insecure)GetProcAddress(pConfig->hModuleGRPC, "leechgrpc_server_create_insecure");
    g_pfn_leechgrpc_server_create_secure_p12 = (pfn_leechgrpc_server_create_secure_p12)GetProcAddress(pConfig->hModuleGRPC, "leechgrpc_server_create_secure_p12");
    g_pfn_leechgrpc_server_shutdown = (pfn_leechgrpc_server_shutdown)GetProcAddress(pConfig->hModuleGRPC, "leechgrpc_server_shutdown");
    if(!g_pfn_leechgrpc_server_create_insecure || !g_pfn_leechgrpc_server_create_secure_p12 || !g_pfn_leechgrpc_server_shutdown) {
        printf("Failed: gRPC: library 'leechgrpc.dll' missing required functions, gRPC functionality is disabled.\n");
        RpcStopGRPC();
        return FALSE;
    }
    if(pConfig->fInsecure) {
        g_hGRPC = g_pfn_leechgrpc_server_create_insecure(
            pConfig->grpc.szListenAddress,
            dwTcpPort,
            NULL,
            LeechGRPC_ReservedSubmitCommand
        );
    } else {
        g_hGRPC = g_pfn_leechgrpc_server_create_secure_p12(
            pConfig->grpc.szListenAddress,
            dwTcpPort,
            NULL, LeechGRPC_ReservedSubmitCommand,
            pConfig->grpc.szTlsClientCaCert,
            pConfig->grpc.szTlsServerP12,
            pConfig->grpc.szTlsServerP12Pass
        );
    }
    if(!g_hGRPC) {
        printf("Failed: gRPC: initialization failed, gRPC functionality is disabled.\n");
        RpcStopGRPC();
        return FALSE;
    }
    if(pConfig->fInsecure) {
        printf(
            "WARNING! Starting LeechAgent in INSECURE gRPC mode!                \n" \
            "     Any user may connect unauthenticated unless firewalled!       \n" \
            "     Ensure that port tcp/%i is properly configured in firewall!\n" \
            "                                                                   \n", dwTcpPort);
    } else {
        printf(
            "INFO: Starting LeechAgent in gRPC mTLS mode!                       \n" \
            "     Ensure that port tcp/%i is properly configured in firewall!\n" \
            "                                                                   \n", dwTcpPort);
    }
    return TRUE;
}

RPC_STATUS RpcStartMSRPC(_In_ BOOL fInsecure, _In_ BOOL fSvc)
{
#if LEECHRPC_ENABLE_NATIVE_RPC
    RPC_STATUS status;
    RPC_CSTR szSPN = NULL;
    // start listening on network (ncacn_ip_tcp - 0.0.0.0:28473)
    // and on local pipe (ncacn_np - \\pipe\\LeechAgent)
    status = RpcServerUseProtseqEpA("ncacn_ip_tcp", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, "30326", NULL);
    if(status) {
        printf("Failed: RPC: Tcp: RpcServerUseProtseqEpA (0x%08x).\n", status);
        return status;
    }
    status = RpcServerUseProtseqEpA("ncacn_np", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, "\\pipe\\LeechAgent", NULL);
    if(status) {
        printf("Failed: RPC: LocalPipe: RpcServerUseProtseqEpA (0x%08x).\n", status);
        return status;
    }
    // Register the interface.
    status = RpcServerRegisterIf2(
        LeechRpc_v1_0_s_ifspec,
        NULL,
        NULL,
        RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH,
        RPC_C_LISTEN_MAX_CALLS_DEFAULT,
        0x02800000,
        fInsecure ? LeechSvcRpc_SecurityCallback_AlwaysAllow : LeechSvcRpc_SecurityCallback
    );
    if(status) {
        printf("Failed: RPC: RpcServerRegisterIf2 (0x%08x).\n", status);
        return status;
    }
    // Register interface and binding with the endpoint mapper.
    status = RpcServerInqBindings(&g_rpc_pbindingVector);
    if(status) {
        printf("Failed: RPC: RpcServerInqBindings (0x%08x).\n", status);
        g_rpc_pbindingVector = NULL;
        return status;
    }
#pragma warning(suppress: 6102)
    status = RpcEpRegister(LeechRpc_v1_0_s_ifspec, g_rpc_pbindingVector, 0, LEECHSVC_TCP_PORT_MSRPC);
    if(status) {
        printf("Failed: RPC: RpcServerInqBindings (0x%08x).\n", status);
        return status;
    }
    // Set security mode.
    if(fInsecure) {
        printf(
            "WARNING! Starting LeechAgent in INSECURE MS-RPC mode!              \n" \
            "     Any user may connect unauthenticated unless firewalled!       \n" \
            "     Ensure that port tcp/28473 is properly configured in firewall!\n" \
            "                                                                   \n");
    } else {
        // enable ntlm security (for local non-domain joined use case).
        status = RpcServerRegisterAuthInfoA("", RPC_C_AUTHN_WINNT, NULL, NULL);
        if(status) {
            printf("Failed: RPC: RpcServerRegisterAuthInfoA (RPC_C_AUTHN_WINNT) (0x%08x).\n", status);
            return status;
        }
        // enable kerberos security.
        status = RpcServerInqDefaultPrincNameA(RPC_C_AUTHN_GSS_KERBEROS, &szSPN);
        if(status) {
            printf("WARN: Kerberos authentication is unavailable.\n");
            printf("      NTLM authentication is available.      \n");
            RpcStringFreeA(&szSPN);
        } else {
            status = RpcServerRegisterAuthInfoA(szSPN, RPC_C_AUTHN_GSS_KERBEROS, NULL, NULL);
            if(status) {
                printf("Failed: RPC: RpcServerRegisterAuthInfoA - SPN: '%s' (0x%08x).\n", szSPN, status);
                RpcStringFreeA(&szSPN);
                return status;
            }
            printf(
                "LeechAgent started with smb/445 and tcp/28473 connectivity.\n" \
                "    Kerberos SPN : ' %s '\n" \
                "    (specify the SPN in the client connection string).\n" \
                "    ---\n" \
                "    For additional info see:\n" \
                "    https://github.com/ufrisk/LeechCore/wiki/LeechAgent\n",
                szSPN);
            if(fSvc) {
                LeechSvcRpc_WriteInfoEventLog("LeechAgent started with kerberos SPN: %s\n", szSPN);
            }
            RpcStringFreeA(&szSPN);
        }
    }
    // start accept calls and return.
    status = RpcServerListen(1, 64, TRUE);
    if(status) {
        printf("Failed: RPC: RpcServerListen (0x%08x).\n", status);
        return status;
    }
    return RPC_S_OK;
#else
    UNREFERENCED_PARAMETER(fInsecure);
    UNREFERENCED_PARAMETER(fSvc);
    printf("INFO: Native MS-RPC transport is disabled at compile time.\n");
    return RPC_S_PROTSEQ_NOT_SUPPORTED;
#endif
}

void RpcStop()
{
    RpcStopGRPC();
    // stop MS-RPC server:
#if LEECHRPC_ENABLE_NATIVE_RPC
#pragma warning(suppress: 6031)
    if(g_rpc_pbindingVector) {
        RpcEpUnregister(LeechRpc_v1_0_s_ifspec, g_rpc_pbindingVector, 0);
        RpcBindingVectorFree(&g_rpc_pbindingVector);
        g_rpc_pbindingVector = NULL;
    }
    RpcMgmtStopServerListening(NULL);
    RpcServerUnregisterIf(0, 0, FALSE);
#endif
}




