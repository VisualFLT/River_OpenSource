// leechrpcclient.c : implementation of the remote procedure call (RPC) client.
//
// (c) Ulf Frisk, 2018-2026
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifdef _WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif
#include "leechcore.h"
#include "leechcore_device.h"
#include "leechcore_internal.h"
#include "leechrpc.h"
#include "util.h"
#include "oscompatibility.h"
#include <leechgrpc.h>

#ifdef _WIN32

#if LEECHRPC_ENABLE_NATIVE_RPC
#include <rpc.h>
#include <ntsecapi.h>
#include <wincred.h>
#include "leechrpc_h.h"
#endif
#include <winhttp.h>

#endif /* _WIN32 */
#if defined(LINUX) || defined(MACOS)

#define LeechRPC_CompressClose(ctxCompress)
#define LeechRPC_CompressInitialize(ctxCompress)                    FALSE
#define LeechRPC_Compress(ctxCompress, pMsg, fCompressDisable)
#define LeechRPC_Decompress(ctxCompress, pMsgIn, ppMsgOut)          FALSE

#endif /* LINUX || MACOS */

//-----------------------------------------------------------------------------
// CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

#ifndef LEECHRPC_CLIENT_PERF_STATS_ENABLE
#define LEECHRPC_CLIENT_PERF_STATS_ENABLE        1
#endif

#ifndef LEECHRPC_CLIENT_PERF_LOG_INTERVAL_MS
#define LEECHRPC_CLIENT_PERF_LOG_INTERVAL_MS     5000
#endif

#ifdef _WIN32
#ifndef LEECHRPC_HTTP_POOL_SIZE_DEFAULT
#define LEECHRPC_HTTP_POOL_SIZE_DEFAULT          32
#endif
#ifndef LEECHRPC_SOCKET_BUFFER_SIZE
#define LEECHRPC_SOCKET_BUFFER_SIZE              (1024 * 1024)
#endif
#ifndef LEECHRPC_HTTP_MUX_MAX_INFLIGHT
#define LEECHRPC_HTTP_MUX_MAX_INFLIGHT          32
#endif
#ifndef LEECHRPC_HTTP_PENDING_MAP_BUCKETS
#define LEECHRPC_HTTP_PENDING_MAP_BUCKETS       64
#endif
#ifndef LEECHRPC_HTTP_BULK_MUX_COUNT
#define LEECHRPC_HTTP_BULK_MUX_COUNT            4
#endif
#ifndef LEECHRPC_HTTP_READ_PARALLELISM_MAX
#define LEECHRPC_HTTP_READ_PARALLELISM_MAX      8
#endif
#ifndef LEECHRPC_HTTP_READ_OPT_ENABLE
#define LEECHRPC_HTTP_READ_OPT_ENABLE           0
#endif

static ULONGLONG LeechRPC_HttpBootstrapPortMix64(_In_ ULONGLONG value)
{
    value ^= value >> 33;
    value *= 0xff51afd7ed558ccdULL;
    value ^= value >> 33;
    value *= 0xc4ceb9fe1a85ec53ULL;
    value ^= value >> 33;
    return value;
}

static DWORD LeechRPC_HttpGetDefaultBootstrapPort()
{
    SYSTEMTIME stUtc = { 0 };
    ULONGLONG seed;
    GetSystemTime(&stUtc);
    seed = ((ULONGLONG)stUtc.wYear << 48)
        | ((ULONGLONG)stUtc.wMonth << 40)
        | ((ULONGLONG)stUtc.wDay << 32)
        | ((ULONGLONG)stUtc.wHour << 24);
    seed = LeechRPC_HttpBootstrapPortMix64(seed ^ 0x4b8de0f19c327a61ULL);
    return 30326 + (DWORD)(seed % (40000 - 30326 + 1));
}

typedef struct tdLEECHRPC_SECURE_SEGMENT {
    const BYTE *pb;
    DWORD cb;
} LEECHRPC_SECURE_SEGMENT, *PLEECHRPC_SECURE_SEGMENT;

typedef struct tdLEECHRPC_HTTP_PENDING_SLOT {
    HANDLE hEvent;
    volatile LONG fInUse;
    DWORD dwRequestID;
    DWORD cbRequest;
    PBYTE pbRequest;
    PBYTE pbFrame;
    DWORD cbFrame;
    DWORD cbSent;
    DWORD cbResponse;
    PBYTE pbResponse;
    BOOL fSuccess;
    BOOL fQueued;
    struct tdLEECHRPC_HTTP_PENDING_SLOT *HashNext;
    struct tdLEECHRPC_HTTP_PENDING_SLOT *Flink;
} LEECHRPC_HTTP_PENDING_SLOT, *PLEECHRPC_HTTP_PENDING_SLOT;

typedef enum tdLEECHRPC_HTTP_ASYNC_IO_OP_TYPE {
    LEECHRPC_HTTP_ASYNC_IO_OP_RECV = 1,
    LEECHRPC_HTTP_ASYNC_IO_OP_SEND = 2
} LEECHRPC_HTTP_ASYNC_IO_OP_TYPE;

typedef struct tdLEECHRPC_HTTP_ASYNC_IO_COMMON {
    OVERLAPPED Ov;
    DWORD dwOpType;
    struct tdLEECHRPC_HTTP_READMUX *pMux;
} LEECHRPC_HTTP_ASYNC_IO_COMMON, *PLEECHRPC_HTTP_ASYNC_IO_COMMON;

typedef struct tdLEECHRPC_HTTP_ASYNC_SEND_OP {
    OVERLAPPED Ov;
    DWORD dwOpType;
    struct tdLEECHRPC_HTTP_READMUX *pMux;
} LEECHRPC_HTTP_ASYNC_SEND_OP, *PLEECHRPC_HTTP_ASYNC_SEND_OP;

typedef struct tdLEECHRPC_HTTP_ASYNC_RECV_OP {
    OVERLAPPED Ov;
    DWORD dwOpType;
    struct tdLEECHRPC_HTTP_READMUX *pMux;
    BOOL fRecvHeader;
    DWORD cbExpected;
    DWORD cbReceived;
    LEECHRPC_SECURE_FRAME_HDR Hdr;
    BYTE rgbHdr[sizeof(LEECHRPC_SECURE_FRAME_HDR)];
    PBYTE pbPayload;
    DWORD cbPayloadAlloc;
} LEECHRPC_HTTP_ASYNC_RECV_OP, *PLEECHRPC_HTTP_ASYNC_RECV_OP;

typedef struct tdLEECHRPC_HTTP_READMUX {
    PLEECHRPC_CLIENT_CONTEXT ctx;
    LEECHRPC_HTTP_CONN Conn;
    CRITICAL_SECTION LockPending;
    HANDLE hPendingSlots;
    HANDLE hIoCp;
    HANDLE hThreadIo;
    volatile LONG fStopThread;
    volatile LONG fThreadIoRunning;
    volatile LONG fSendInFlight;
    DWORD cPendingMax;
    PLEECHRPC_HTTP_PENDING_SLOT pSendHead;
    PLEECHRPC_HTTP_PENDING_SLOT pSendTail;
    PLEECHRPC_HTTP_PENDING_SLOT PendingMap[LEECHRPC_HTTP_PENDING_MAP_BUCKETS];
    PLEECHRPC_HTTP_ASYNC_RECV_OP pRecvOp;
    LEECHRPC_HTTP_ASYNC_SEND_OP SendOp;
    LEECHRPC_HTTP_PENDING_SLOT Pending[LEECHRPC_HTTP_MUX_MAX_INFLIGHT];
} LEECHRPC_HTTP_READMUX, *PLEECHRPC_HTTP_READMUX;

typedef struct tdLEECHRPC_READSCATTER_CHUNK {
    DWORD cMEMs;
    PPMEM_SCATTER ppMEMs;
} LEECHRPC_READSCATTER_CHUNK, *PLEECHRPC_READSCATTER_CHUNK;

typedef struct tdLEECHRPC_READSCATTER_PARALLEL_TASK {
    PLC_CONTEXT ctxLC;
    DWORD cChunk;
    PLEECHRPC_READSCATTER_CHUNK pChunks;
} LEECHRPC_READSCATTER_PARALLEL_TASK, *PLEECHRPC_READSCATTER_PARALLEL_TASK;

typedef struct tdLEECHRPC_READSCATTER_BATCH {
    HANDLE hDoneEvent;
    volatile LONG cPending;
} LEECHRPC_READSCATTER_BATCH, *PLEECHRPC_READSCATTER_BATCH;

typedef struct tdLEECHRPC_READSCATTER_WORKITEM {
    PLC_CONTEXT ctxLC;
    DWORD cMEMs;
    PPMEM_SCATTER ppMEMs;
    PLEECHRPC_READSCATTER_BATCH pBatch;
    struct tdLEECHRPC_READSCATTER_WORKITEM *Flink;
} LEECHRPC_READSCATTER_WORKITEM, *PLEECHRPC_READSCATTER_WORKITEM;

static const BYTE g_LeechRpcSecurePsk[32] = {
    0x6d, 0x2a, 0x4f, 0x91, 0xc3, 0x7b, 0x11, 0xe8,
    0x52, 0x39, 0xaa, 0x6f, 0x0d, 0xb4, 0x83, 0x1c,
    0x74, 0xde, 0x25, 0x90, 0x4a, 0xf2, 0x68, 0x17,
    0xbe, 0x33, 0x5c, 0x8d, 0xe1, 0x46, 0x79, 0x0b
};

static BCRYPT_ALG_HANDLE g_hLeechRpcSecureAlgAes = NULL;
static BCRYPT_ALG_HANDLE g_hLeechRpcSecureAlgHmac = NULL;
static INIT_ONCE g_LeechRpcSecureInitOnce = INIT_ONCE_STATIC_INIT;
static INIT_ONCE g_LeechRpcReadScatterPoolInitOnce = INIT_ONCE_STATIC_INIT;
static BOOL LeechRPC_SocketSendAll(_In_ SOCKET s, _In_reads_bytes_(cbData) const BYTE *pbData, _In_ DWORD cbData);
static BOOL LeechRPC_SocketRecvAll(_In_ SOCKET s, _Out_writes_bytes_(cbData) BYTE *pbData, _In_ DWORD cbData);
static BOOL LeechRPC_IsDataPlaneMsg(_In_ LEECHRPC_MSGTYPE tpMsg);
static DWORD LeechRPC_SelectDataMuxIndex(_Inout_ PLEECHRPC_CLIENT_CONTEXT ctx, _In_ DWORD dwRequestID);
static DWORD LeechRPC_HttpReadMuxPendingBucketIndex(_In_ DWORD dwRequestID);
static VOID LeechRPC_HttpReadMuxPendingInsertLocked(_Inout_ PLEECHRPC_HTTP_READMUX pMux, _Inout_ PLEECHRPC_HTTP_PENDING_SLOT pSlot);
static VOID LeechRPC_HttpReadMuxPendingRemoveLocked(_Inout_ PLEECHRPC_HTTP_READMUX pMux, _Inout_ PLEECHRPC_HTTP_PENDING_SLOT pSlot);
static PLEECHRPC_HTTP_PENDING_SLOT LeechRPC_HttpReadMuxPendingFindLocked(_Inout_ PLEECHRPC_HTTP_READMUX pMux, _In_ DWORD dwRequestID);
static CRITICAL_SECTION g_LeechRpcReadScatterPoolLock;
static HANDLE g_hLeechRpcReadScatterPoolSem = NULL;
static HANDLE g_ahLeechRpcReadScatterPoolWorkers[LEECHRPC_HTTP_READ_PARALLELISM_MAX] = { 0 };
static volatile LONG g_fLeechRpcReadScatterPoolStop = FALSE;
static PLEECHRPC_READSCATTER_WORKITEM g_pLeechRpcReadScatterPoolHead = NULL;
static PLEECHRPC_READSCATTER_WORKITEM g_pLeechRpcReadScatterPoolTail = NULL;

static BOOL CALLBACK LeechRPC_SecureInitializeProviders(_In_ PINIT_ONCE InitOnce, _In_opt_ PVOID Parameter, _Out_opt_ PVOID *Context)
{
    NTSTATUS nt = 0;
    UNREFERENCED_PARAMETER(InitOnce);
    UNREFERENCED_PARAMETER(Parameter);
    UNREFERENCED_PARAMETER(Context);
    nt = BCryptOpenAlgorithmProvider(&g_hLeechRpcSecureAlgAes, BCRYPT_AES_ALGORITHM, NULL, 0);
    if(!BCRYPT_SUCCESS(nt)) { goto fail; }
    nt = BCryptSetProperty(
        g_hLeechRpcSecureAlgAes,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        (ULONG)((wcslen(BCRYPT_CHAIN_MODE_GCM) + 1) * sizeof(WCHAR)),
        0);
    if(!BCRYPT_SUCCESS(nt)) { goto fail; }
    nt = BCryptOpenAlgorithmProvider(&g_hLeechRpcSecureAlgHmac, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if(!BCRYPT_SUCCESS(nt)) { goto fail; }
    return TRUE;
fail:
    if(g_hLeechRpcSecureAlgAes) {
        BCryptCloseAlgorithmProvider(g_hLeechRpcSecureAlgAes, 0);
        g_hLeechRpcSecureAlgAes = NULL;
    }
    if(g_hLeechRpcSecureAlgHmac) {
        BCryptCloseAlgorithmProvider(g_hLeechRpcSecureAlgHmac, 0);
        g_hLeechRpcSecureAlgHmac = NULL;
    }
    return FALSE;
}

static BOOL LeechRPC_SecureEnsureInitialized()
{
    return InitOnceExecuteOnce(&g_LeechRpcSecureInitOnce, LeechRPC_SecureInitializeProviders, NULL, NULL) ? TRUE : FALSE;
}

static VOID LeechRPC_SecureDestroyConnection_NoLock(_Inout_ PLEECHRPC_HTTP_CONN pConn)
{
    if(pConn->hCryptoKeyEncrypt) {
        BCryptDestroyKey((BCRYPT_KEY_HANDLE)pConn->hCryptoKeyEncrypt);
        pConn->hCryptoKeyEncrypt = NULL;
    }
    if(pConn->hCryptoKeyDecrypt) {
        BCryptDestroyKey((BCRYPT_KEY_HANDLE)pConn->hCryptoKeyDecrypt);
        pConn->hCryptoKeyDecrypt = NULL;
    }
    if(pConn->pbCryptoKeyObjectEncrypt) {
        SecureZeroMemory(pConn->pbCryptoKeyObjectEncrypt, pConn->cbCryptoKeyObjectEncrypt);
        LocalFree(pConn->pbCryptoKeyObjectEncrypt);
        pConn->pbCryptoKeyObjectEncrypt = NULL;
    }
    if(pConn->pbCryptoKeyObjectDecrypt) {
        SecureZeroMemory(pConn->pbCryptoKeyObjectDecrypt, pConn->cbCryptoKeyObjectDecrypt);
        LocalFree(pConn->pbCryptoKeyObjectDecrypt);
        pConn->pbCryptoKeyObjectDecrypt = NULL;
    }
    pConn->cbCryptoKeyObjectEncrypt = 0;
    pConn->cbCryptoKeyObjectDecrypt = 0;
    if(pConn->pbTxFrame) {
        SecureZeroMemory(pConn->pbTxFrame, pConn->cbTxFrameAlloc);
        LocalFree(pConn->pbTxFrame);
        pConn->pbTxFrame = NULL;
    }
    pConn->cbTxFrameAlloc = 0;
    SecureZeroMemory(pConn->rgbCryptoNonceBaseEncrypt, sizeof(pConn->rgbCryptoNonceBaseEncrypt));
    SecureZeroMemory(pConn->rgbCryptoNonceBaseDecrypt, sizeof(pConn->rgbCryptoNonceBaseDecrypt));
    pConn->qwCryptoSeqTx = 0;
    pConn->qwCryptoSeqRx = 0;
    pConn->fCryptoReady = FALSE;
}

static BOOL LeechRPC_SecureEnsureTxFrame_NoLock(_Inout_ PLEECHRPC_HTTP_CONN pConn, _In_ DWORD cbFrame)
{
    PBYTE pbNew;
    DWORD cbAlloc;
    if(cbFrame <= pConn->cbTxFrameAlloc) {
        return TRUE;
    }
    cbAlloc = max(cbFrame, 0x4000U);
    pbNew = (PBYTE)LocalAlloc(LMEM_FIXED, cbAlloc);
    if(!pbNew) {
        return FALSE;
    }
    if(pConn->pbTxFrame) {
        SecureZeroMemory(pConn->pbTxFrame, pConn->cbTxFrameAlloc);
        LocalFree(pConn->pbTxFrame);
    }
    pConn->pbTxFrame = pbNew;
    pConn->cbTxFrameAlloc = cbAlloc;
    return TRUE;
}

static BOOL LeechRPC_SecureHmacSha256(
    _In_reads_bytes_(cbKey) const BYTE *pbKey,
    _In_ DWORD cbKey,
    _In_reads_(cSeg) const LEECHRPC_SECURE_SEGMENT *pSeg,
    _In_ DWORD cSeg,
    _Out_writes_bytes_(LEECHRPC_SECURE_MAC_SIZE) BYTE *rgbMac)
{
    NTSTATUS nt;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PBYTE pbHashObject = NULL;
    DWORD i;
    ULONG cbHashObject = 0, cbResult = 0;
    if(!LeechRPC_SecureEnsureInitialized()) { return FALSE; }
    nt = BCryptGetProperty(g_hLeechRpcSecureAlgHmac, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbHashObject, sizeof(cbHashObject), &cbResult, 0);
    if(!BCRYPT_SUCCESS(nt) || !cbHashObject) { return FALSE; }
    pbHashObject = (PBYTE)LocalAlloc(0, cbHashObject);
    if(!pbHashObject) { return FALSE; }
    nt = BCryptCreateHash(g_hLeechRpcSecureAlgHmac, &hHash, pbHashObject, cbHashObject, (PUCHAR)pbKey, cbKey, 0);
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

static BOOL LeechRPC_SecureCreateKey(
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
    if(!LeechRPC_SecureEnsureInitialized()) { return FALSE; }
    nt = BCryptGetProperty(g_hLeechRpcSecureAlgAes, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObject, sizeof(cbKeyObject), &cbResult, 0);
    if(!BCRYPT_SUCCESS(nt) || !cbKeyObject) { return FALSE; }
    pbKeyObject = (PBYTE)LocalAlloc(0, cbKeyObject);
    if(!pbKeyObject) { return FALSE; }
    nt = BCryptGenerateSymmetricKey(g_hLeechRpcSecureAlgAes, &hKey, pbKeyObject, cbKeyObject, (PUCHAR)pbKeyMaterial, LEECHRPC_SECURE_MAC_SIZE, 0);
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

static VOID LeechRPC_SecureBuildNonce(_In_reads_bytes_(LEECHRPC_SECURE_NONCE_SIZE) const BYTE *pbBase, _In_ QWORD qwSeq, _Out_writes_bytes_(LEECHRPC_SECURE_NONCE_SIZE) BYTE *pbNonce)
{
    DWORD i;
    memcpy(pbNonce, pbBase, LEECHRPC_SECURE_NONCE_SIZE);
    for(i = 0; i < sizeof(QWORD); i++) {
        pbNonce[LEECHRPC_SECURE_NONCE_SIZE - 1 - i] ^= (BYTE)(qwSeq >> (8 * i));
    }
}

static BOOL LeechRPC_SecureSendMessage_NoLock(
    _Inout_ PLEECHRPC_HTTP_CONN pConn,
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
    Hdr.qwSeq = ++pConn->qwCryptoSeqTx;
    Hdr.cbFrame = sizeof(LEECHRPC_SECURE_FRAME_HDR) + cbPlain + LEECHRPC_SECURE_TAG_SIZE;
    if(!LeechRPC_SecureEnsureTxFrame_NoLock(pConn, Hdr.cbFrame)) { return FALSE; }
    pbFrame = pConn->pbTxFrame;
    memcpy(pbFrame, &Hdr, sizeof(Hdr));
    pbCipher = pbFrame + sizeof(Hdr);
    pbTag = pbCipher + cbPlain;
    LeechRPC_SecureBuildNonce(pConn->rgbCryptoNonceBaseEncrypt, Hdr.qwSeq, rgbNonce);
    BCRYPT_INIT_AUTH_MODE_INFO(AuthInfo);
    AuthInfo.pbNonce = rgbNonce;
    AuthInfo.cbNonce = sizeof(rgbNonce);
    AuthInfo.pbAuthData = pbFrame;
    AuthInfo.cbAuthData = sizeof(Hdr);
    AuthInfo.pbTag = pbTag;
    AuthInfo.cbTag = LEECHRPC_SECURE_TAG_SIZE;
    nt = BCryptEncrypt((BCRYPT_KEY_HANDLE)pConn->hCryptoKeyEncrypt, (PUCHAR)pbPlain, cbPlain, &AuthInfo, NULL, 0, pbCipher, cbPlain, &cbOut, 0);
    SecureZeroMemory(rgbNonce, sizeof(rgbNonce));
    if(!BCRYPT_SUCCESS(nt) || (cbOut != cbPlain)) {
        return FALSE;
    }
    return LeechRPC_SocketSendAll(pConn->s, pbFrame, Hdr.cbFrame);
}

static BOOL LeechRPC_SecureRecvMessage_NoLock(
    _Inout_ PLEECHRPC_HTTP_CONN pConn,
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
    if(!LeechRPC_SocketRecvAll(pConn->s, (PBYTE)&Hdr, sizeof(Hdr))) { return FALSE; }
    if((Hdr.dwMagic != LEECHRPC_SECURE_FRAME_MAGIC) || (Hdr.dwVersion != LEECHRPC_SECURE_VERSION) || (Hdr.cbFrame < sizeof(Hdr) + LEECHRPC_SECURE_TAG_SIZE + sizeof(LEECHRPC_MSG_HDR)) || (Hdr.cbFrame >= 0x10000000) || (Hdr.qwSeq != (pConn->qwCryptoSeqRx + 1))) {
        return FALSE;
    }
    cbCipher = Hdr.cbFrame - sizeof(Hdr) - LEECHRPC_SECURE_TAG_SIZE;
    pbPayload = (PBYTE)LocalAlloc(LMEM_FIXED, cbCipher + LEECHRPC_SECURE_TAG_SIZE);
    pbPlain = (PBYTE)LocalAlloc(LMEM_FIXED, cbCipher);
    if(!pbPayload || !pbPlain) { goto fail; }
    if(!LeechRPC_SocketRecvAll(pConn->s, pbPayload, cbCipher + LEECHRPC_SECURE_TAG_SIZE)) { goto fail; }
    LeechRPC_SecureBuildNonce(pConn->rgbCryptoNonceBaseDecrypt, Hdr.qwSeq, rgbNonce);
    BCRYPT_INIT_AUTH_MODE_INFO(AuthInfo);
    AuthInfo.pbNonce = rgbNonce;
    AuthInfo.cbNonce = sizeof(rgbNonce);
    AuthInfo.pbAuthData = (PUCHAR)&Hdr;
    AuthInfo.cbAuthData = sizeof(Hdr);
    AuthInfo.pbTag = pbPayload + cbCipher;
    AuthInfo.cbTag = LEECHRPC_SECURE_TAG_SIZE;
    nt = BCryptDecrypt((BCRYPT_KEY_HANDLE)pConn->hCryptoKeyDecrypt, pbPayload, cbCipher, &AuthInfo, NULL, 0, pbPlain, cbCipher, &cbOut, 0);
    SecureZeroMemory(rgbNonce, sizeof(rgbNonce));
    if(!BCRYPT_SUCCESS(nt) || (cbOut != cbCipher)) { goto fail; }
    pConn->qwCryptoSeqRx = Hdr.qwSeq;
    LocalFree(pbPayload);
    *ppbPlain = pbPlain;
    *pcbPlain = cbCipher;
    return TRUE;
fail:
    LocalFree(pbPayload);
    LocalFree(pbPlain);
    return FALSE;
}

static BOOL LeechRPC_SecureBuildMessageFrameAlloc_NoLock(
    _Inout_ PLEECHRPC_HTTP_CONN pConn,
    _In_reads_bytes_(cbPlain) const BYTE *pbPlain,
    _In_ DWORD cbPlain,
    _Outptr_result_bytebuffer_(*pcbFrame) PBYTE *ppbFrame,
    _Out_ DWORD *pcbFrame)
{
    NTSTATUS nt;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO AuthInfo;
    LEECHRPC_SECURE_FRAME_HDR Hdr = { 0 };
    PBYTE pbFrame = NULL;
    PBYTE pbCipher;
    PBYTE pbTag;
    BYTE rgbNonce[LEECHRPC_SECURE_NONCE_SIZE];
    ULONG cbOut = 0;
    *ppbFrame = NULL;
    *pcbFrame = 0;
    Hdr.dwMagic = LEECHRPC_SECURE_FRAME_MAGIC;
    Hdr.dwVersion = LEECHRPC_SECURE_VERSION;
    Hdr.qwSeq = ++pConn->qwCryptoSeqTx;
    Hdr.cbFrame = sizeof(LEECHRPC_SECURE_FRAME_HDR) + cbPlain + LEECHRPC_SECURE_TAG_SIZE;
    pbFrame = (PBYTE)LocalAlloc(LMEM_FIXED, Hdr.cbFrame);
    if(!pbFrame) {
        return FALSE;
    }
    memcpy(pbFrame, &Hdr, sizeof(Hdr));
    pbCipher = pbFrame + sizeof(Hdr);
    pbTag = pbCipher + cbPlain;
    LeechRPC_SecureBuildNonce(pConn->rgbCryptoNonceBaseEncrypt, Hdr.qwSeq, rgbNonce);
    BCRYPT_INIT_AUTH_MODE_INFO(AuthInfo);
    AuthInfo.pbNonce = rgbNonce;
    AuthInfo.cbNonce = sizeof(rgbNonce);
    AuthInfo.pbAuthData = pbFrame;
    AuthInfo.cbAuthData = sizeof(Hdr);
    AuthInfo.pbTag = pbTag;
    AuthInfo.cbTag = LEECHRPC_SECURE_TAG_SIZE;
    nt = BCryptEncrypt((BCRYPT_KEY_HANDLE)pConn->hCryptoKeyEncrypt, (PUCHAR)pbPlain, cbPlain, &AuthInfo, NULL, 0, pbCipher, cbPlain, &cbOut, 0);
    SecureZeroMemory(rgbNonce, sizeof(rgbNonce));
    if(!BCRYPT_SUCCESS(nt) || (cbOut != cbPlain)) {
        LocalFree(pbFrame);
        return FALSE;
    }
    *ppbFrame = pbFrame;
    *pcbFrame = Hdr.cbFrame;
    return TRUE;
}

static BOOL LeechRPC_SecureDecryptReceivedMessage_NoLock(
    _Inout_ PLEECHRPC_HTTP_CONN pConn,
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
        (pHdr->cbFrame != sizeof(LEECHRPC_SECURE_FRAME_HDR) + cbPayload) ||
        (pHdr->cbFrame < sizeof(LEECHRPC_SECURE_FRAME_HDR) + LEECHRPC_SECURE_TAG_SIZE + sizeof(LEECHRPC_MSG_HDR)) ||
        (pHdr->cbFrame >= 0x10000000) ||
        (pHdr->qwSeq != (pConn->qwCryptoSeqRx + 1))) {
        return FALSE;
    }
    if(cbPayload < LEECHRPC_SECURE_TAG_SIZE + sizeof(LEECHRPC_MSG_HDR)) {
        return FALSE;
    }
    cbCipher = cbPayload - LEECHRPC_SECURE_TAG_SIZE;
    pbPlain = (PBYTE)LocalAlloc(LMEM_FIXED, cbCipher);
    if(!pbPlain) {
        return FALSE;
    }
    LeechRPC_SecureBuildNonce(pConn->rgbCryptoNonceBaseDecrypt, pHdr->qwSeq, rgbNonce);
    BCRYPT_INIT_AUTH_MODE_INFO(AuthInfo);
    AuthInfo.pbNonce = rgbNonce;
    AuthInfo.cbNonce = sizeof(rgbNonce);
    AuthInfo.pbAuthData = (PUCHAR)pHdr;
    AuthInfo.cbAuthData = sizeof(*pHdr);
    AuthInfo.pbTag = pbPayload + cbCipher;
    AuthInfo.cbTag = LEECHRPC_SECURE_TAG_SIZE;
    nt = BCryptDecrypt((BCRYPT_KEY_HANDLE)pConn->hCryptoKeyDecrypt, pbPayload, cbCipher, &AuthInfo, NULL, 0, pbPlain, cbCipher, &cbOut, 0);
    SecureZeroMemory(rgbNonce, sizeof(rgbNonce));
    if(!BCRYPT_SUCCESS(nt) || (cbOut != cbCipher)) {
        LocalFree(pbPlain);
        return FALSE;
    }
    pConn->qwCryptoSeqRx = pHdr->qwSeq;
    *ppbPlain = pbPlain;
    *pcbPlain = cbCipher;
    return TRUE;
}

static BOOL LeechRPC_SecureDeriveConnectionKeys(
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
    LEECHRPC_SECURE_SEGMENT Seg[3];
    BYTE rgbTmp[LEECHRPC_SECURE_MAC_SIZE];
    Seg[1].pb = pbClientRandom;
    Seg[1].cb = LEECHRPC_SECURE_RANDOM_SIZE;
    Seg[2].pb = pbServerRandom;
    Seg[2].cb = LEECHRPC_SECURE_RANDOM_SIZE;
    Seg[0].pb = szKeyC2S;
    Seg[0].cb = sizeof(szKeyC2S) - 1;
    if(!LeechRPC_SecureHmacSha256(g_LeechRpcSecurePsk, sizeof(g_LeechRpcSecurePsk), Seg, 3, pbKeyEncrypt)) { return FALSE; }
    Seg[0].pb = szKeyS2C;
    Seg[0].cb = sizeof(szKeyS2C) - 1;
    if(!LeechRPC_SecureHmacSha256(g_LeechRpcSecurePsk, sizeof(g_LeechRpcSecurePsk), Seg, 3, pbKeyDecrypt)) { return FALSE; }
    Seg[0].pb = szNonceC2S;
    Seg[0].cb = sizeof(szNonceC2S) - 1;
    if(!LeechRPC_SecureHmacSha256(g_LeechRpcSecurePsk, sizeof(g_LeechRpcSecurePsk), Seg, 3, rgbTmp)) { return FALSE; }
    memcpy(pbNonceEncrypt, rgbTmp, LEECHRPC_SECURE_NONCE_SIZE);
    Seg[0].pb = szNonceS2C;
    Seg[0].cb = sizeof(szNonceS2C) - 1;
    if(!LeechRPC_SecureHmacSha256(g_LeechRpcSecurePsk, sizeof(g_LeechRpcSecurePsk), Seg, 3, rgbTmp)) { return FALSE; }
    memcpy(pbNonceDecrypt, rgbTmp, LEECHRPC_SECURE_NONCE_SIZE);
    SecureZeroMemory(rgbTmp, sizeof(rgbTmp));
    return TRUE;
}

static BOOL LeechRPC_SecureHandshake_NoLock(_Inout_ PLEECHRPC_HTTP_CONN pConn)
{
    static const BYTE szHelloClient[] = "rv-hello-client";
    static const BYTE szHelloServer[] = "rv-hello-server";
    LEECHRPC_SECURE_HELLO HelloClient = { 0 };
    LEECHRPC_SECURE_HELLO HelloServer = { 0 };
    LEECHRPC_SECURE_SEGMENT Seg[3];
    BYTE rgbMacExpected[LEECHRPC_SECURE_MAC_SIZE];
    BYTE rgbKeyEncrypt[LEECHRPC_SECURE_MAC_SIZE];
    BYTE rgbKeyDecrypt[LEECHRPC_SECURE_MAC_SIZE];
    BYTE rgbNonceEncrypt[LEECHRPC_SECURE_NONCE_SIZE];
    BYTE rgbNonceDecrypt[LEECHRPC_SECURE_NONCE_SIZE];
    if(pConn->fCryptoReady) { return TRUE; }
    if(!LeechRPC_SecureEnsureInitialized()) { return FALSE; }
    HelloClient.dwMagic = LEECHRPC_SECURE_HELLO_CLIENT_MAGIC;
    HelloClient.dwVersion = LEECHRPC_SECURE_VERSION;
    Util_GenRandom(HelloClient.rgbRandom, sizeof(HelloClient.rgbRandom));
    Seg[0].pb = szHelloClient;
    Seg[0].cb = sizeof(szHelloClient) - 1;
    Seg[1].pb = (const BYTE*)&HelloClient.dwVersion;
    Seg[1].cb = sizeof(HelloClient.dwVersion);
    Seg[2].pb = HelloClient.rgbRandom;
    Seg[2].cb = sizeof(HelloClient.rgbRandom);
    if(!LeechRPC_SecureHmacSha256(g_LeechRpcSecurePsk, sizeof(g_LeechRpcSecurePsk), Seg, 3, HelloClient.rgbMac)) { goto fail; }
    if(!LeechRPC_SocketSendAll(pConn->s, (const BYTE*)&HelloClient, sizeof(HelloClient))) { goto fail; }
    if(!LeechRPC_SocketRecvAll(pConn->s, (PBYTE)&HelloServer, sizeof(HelloServer))) { goto fail; }
    if((HelloServer.dwMagic != LEECHRPC_SECURE_HELLO_SERVER_MAGIC) || (HelloServer.dwVersion != LEECHRPC_SECURE_VERSION)) { goto fail; }
    Seg[0].pb = szHelloServer;
    Seg[0].cb = sizeof(szHelloServer) - 1;
    Seg[1].pb = HelloClient.rgbRandom;
    Seg[1].cb = sizeof(HelloClient.rgbRandom);
    Seg[2].pb = HelloServer.rgbRandom;
    Seg[2].cb = sizeof(HelloServer.rgbRandom);
    if(!LeechRPC_SecureHmacSha256(g_LeechRpcSecurePsk, sizeof(g_LeechRpcSecurePsk), Seg, 3, rgbMacExpected)) { goto fail; }
    if(memcmp(rgbMacExpected, HelloServer.rgbMac, sizeof(rgbMacExpected))) { goto fail; }
    if(!LeechRPC_SecureDeriveConnectionKeys(HelloClient.rgbRandom, HelloServer.rgbRandom, rgbKeyEncrypt, rgbKeyDecrypt, rgbNonceEncrypt, rgbNonceDecrypt)) { goto fail; }
    if(!LeechRPC_SecureCreateKey(rgbKeyEncrypt, &pConn->hCryptoKeyEncrypt, &pConn->pbCryptoKeyObjectEncrypt, &pConn->cbCryptoKeyObjectEncrypt)) { goto fail; }
    if(!LeechRPC_SecureCreateKey(rgbKeyDecrypt, &pConn->hCryptoKeyDecrypt, &pConn->pbCryptoKeyObjectDecrypt, &pConn->cbCryptoKeyObjectDecrypt)) { goto fail; }
    memcpy(pConn->rgbCryptoNonceBaseEncrypt, rgbNonceEncrypt, sizeof(rgbNonceEncrypt));
    memcpy(pConn->rgbCryptoNonceBaseDecrypt, rgbNonceDecrypt, sizeof(rgbNonceDecrypt));
    pConn->qwCryptoSeqTx = 0;
    pConn->qwCryptoSeqRx = 0;
    pConn->fCryptoReady = TRUE;
    SecureZeroMemory(rgbMacExpected, sizeof(rgbMacExpected));
    SecureZeroMemory(rgbKeyEncrypt, sizeof(rgbKeyEncrypt));
    SecureZeroMemory(rgbKeyDecrypt, sizeof(rgbKeyDecrypt));
    SecureZeroMemory(rgbNonceEncrypt, sizeof(rgbNonceEncrypt));
    SecureZeroMemory(rgbNonceDecrypt, sizeof(rgbNonceDecrypt));
    SecureZeroMemory(&HelloClient, sizeof(HelloClient));
    SecureZeroMemory(&HelloServer, sizeof(HelloServer));
    return TRUE;
fail:
    LeechRPC_SecureDestroyConnection_NoLock(pConn);
    SecureZeroMemory(rgbMacExpected, sizeof(rgbMacExpected));
    SecureZeroMemory(rgbKeyEncrypt, sizeof(rgbKeyEncrypt));
    SecureZeroMemory(rgbKeyDecrypt, sizeof(rgbKeyDecrypt));
    SecureZeroMemory(rgbNonceEncrypt, sizeof(rgbNonceEncrypt));
    SecureZeroMemory(rgbNonceDecrypt, sizeof(rgbNonceDecrypt));
    SecureZeroMemory(&HelloClient, sizeof(HelloClient));
    SecureZeroMemory(&HelloServer, sizeof(HelloServer));
    return FALSE;
}
#endif

#if LEECHRPC_CLIENT_PERF_STATS_ENABLE && defined(_WIN32)
typedef struct tdLEECHRPC_CLIENT_PERF {
    BOOL fStarted;
    QWORD qwStartTickCount64;
    QWORD qwLastLogTickCount64;
    QWORD cReqTotal;
    QWORD cReqFail;
    QWORD cbTxTotal;
    QWORD cbRxTotal;
    QWORD cReadReq;
    QWORD cbReadReqTotal;
    QWORD cbReadRspTotal;
    QWORD cRttSamples;
    QWORD qwRttTotalMs;
    DWORD dwRttMaxMs;
    QWORD qwServerLastLogTickCount64;
    BOOL fServerPerfBaseValid;
    BOOL fServerPerfUnsupported;
    LEECHRPC_PERF_SNAPSHOT ServerPerfBase;
    CRITICAL_SECTION Lock;
    BOOL fLockInitialized;
} LEECHRPC_CLIENT_PERF, *PLEECHRPC_CLIENT_PERF;

static LEECHRPC_CLIENT_PERF g_LeechRpcClientPerf = { 0 };
static INIT_ONCE g_LeechRpcClientPerfInitOnce = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK LeechRPC_ClientPerfInit(_In_ PINIT_ONCE InitOnce, _In_opt_ PVOID Parameter, _Out_opt_ PVOID *Context)
{
    UNREFERENCED_PARAMETER(InitOnce);
    UNREFERENCED_PARAMETER(Parameter);
    UNREFERENCED_PARAMETER(Context);
    InitializeCriticalSection(&g_LeechRpcClientPerf.Lock);
    g_LeechRpcClientPerf.fLockInitialized = TRUE;
    return TRUE;
}

static BOOL LeechRPC_ClientPerfEnsureInitialized()
{
    return InitOnceExecuteOnce(&g_LeechRpcClientPerfInitOnce, LeechRPC_ClientPerfInit, NULL, NULL) ? TRUE : FALSE;
}

static VOID LeechRPC_ClientPerfLogFile(_In_z_ _Printf_format_string_ char const* const _Format, ...)
{
    CHAR szBuffer[0x1000] = { 0 };
    CHAR szLine[0x1100] = { 0 };
    SYSTEMTIME st = { 0 };
    FILE *f = NULL;
    va_list argptr;
    if(!LeechRPC_ClientPerfEnsureInitialized()) { return; }
    GetLocalTime(&st);
    va_start(argptr, _Format);
    _vsnprintf_s(szBuffer, _countof(szBuffer), _TRUNCATE, _Format, argptr);
    va_end(argptr);
    _snprintf_s(szLine, _countof(szLine), _TRUNCATE, "[%04u-%02u-%02u %02u:%02u:%02u.%03u] %s",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, szBuffer);
    CreateDirectoryA("C:\\pmem_clientlog", NULL);
    if(!fopen_s(&f, "C:\\pmem_clientlog\\rpc_metrics.log", "a")) {
        fputs(szLine, f);
        fputs("\n", f);
        fclose(f);
    }
}

static VOID LeechRPC_ClientPerfReset()
{
    if(!LeechRPC_ClientPerfEnsureInitialized()) { return; }
    EnterCriticalSection(&g_LeechRpcClientPerf.Lock);
    g_LeechRpcClientPerf.fStarted = TRUE;
    g_LeechRpcClientPerf.qwStartTickCount64 = GetTickCount64();
    g_LeechRpcClientPerf.qwLastLogTickCount64 = 0;
    g_LeechRpcClientPerf.cReqTotal = 0;
    g_LeechRpcClientPerf.cReqFail = 0;
    g_LeechRpcClientPerf.cbTxTotal = 0;
    g_LeechRpcClientPerf.cbRxTotal = 0;
    g_LeechRpcClientPerf.cReadReq = 0;
    g_LeechRpcClientPerf.cbReadReqTotal = 0;
    g_LeechRpcClientPerf.cbReadRspTotal = 0;
    g_LeechRpcClientPerf.cRttSamples = 0;
    g_LeechRpcClientPerf.qwRttTotalMs = 0;
    g_LeechRpcClientPerf.dwRttMaxMs = 0;
    g_LeechRpcClientPerf.qwServerLastLogTickCount64 = 0;
    g_LeechRpcClientPerf.fServerPerfBaseValid = FALSE;
    g_LeechRpcClientPerf.fServerPerfUnsupported = FALSE;
    ZeroMemory(&g_LeechRpcClientPerf.ServerPerfBase, sizeof(g_LeechRpcClientPerf.ServerPerfBase));
    LeaveCriticalSection(&g_LeechRpcClientPerf.Lock);
}

static VOID LeechRPC_ClientPerfOnRequest(_In_ LEECHRPC_MSGTYPE tpReq, _In_ DWORD cbTx, _In_ DWORD cbRx, _In_ DWORD dwRttMs, _In_ BOOL fSuccess, _In_opt_ PLEECHRPC_MSG_HDR pReq, _In_opt_ PLEECHRPC_MSG_HDR pRsp)
{
    if(!LeechRPC_ClientPerfEnsureInitialized()) { return; }
    EnterCriticalSection(&g_LeechRpcClientPerf.Lock);
    if(g_LeechRpcClientPerf.fStarted) {
        if(tpReq == LEECHRPC_MSGTYPE_PERF_REQ) {
            LeaveCriticalSection(&g_LeechRpcClientPerf.Lock);
            return;
        }
        g_LeechRpcClientPerf.cReqTotal++;
        g_LeechRpcClientPerf.cbTxTotal += cbTx;
        g_LeechRpcClientPerf.cbRxTotal += cbRx;
        g_LeechRpcClientPerf.cRttSamples++;
        g_LeechRpcClientPerf.qwRttTotalMs += dwRttMs;
        if(dwRttMs > g_LeechRpcClientPerf.dwRttMaxMs) {
            g_LeechRpcClientPerf.dwRttMaxMs = dwRttMs;
        }
        if(!fSuccess) {
            g_LeechRpcClientPerf.cReqFail++;
        }
        if(fSuccess && (tpReq == LEECHRPC_MSGTYPE_READSCATTER_REQ) && pReq && pRsp && (pRsp->tpMsg == LEECHRPC_MSGTYPE_READSCATTER_RSP)) {
            DWORD cMEMsRsp = (DWORD)((PLEECHRPC_MSG_BIN)pRsp)->qwData[0];
            DWORD cbRspPayload = ((PLEECHRPC_MSG_BIN)pRsp)->cb;
            DWORD cbRspData = 0;
            if(cbRspPayload >= cMEMsRsp * sizeof(MEM_SCATTER)) {
                cbRspData = cbRspPayload - (cMEMsRsp * sizeof(MEM_SCATTER));
            }
            g_LeechRpcClientPerf.cReadReq++;
            g_LeechRpcClientPerf.cbReadReqTotal += (DWORD)((PLEECHRPC_MSG_BIN)pReq)->qwData[1];
            g_LeechRpcClientPerf.cbReadRspTotal += cbRspData;
        }
    }
    LeaveCriticalSection(&g_LeechRpcClientPerf.Lock);
}

static VOID LeechRPC_ClientPerfLogSnapshot(_In_ BOOL fForce)
{
    if(!LeechRPC_ClientPerfEnsureInitialized()) { return; }
    QWORD qwNow, qwElapsedMs;
    QWORD cReqPerSec, cbTxPerSec, cbRxPerSec, dwRttAvg;
    QWORD cReqTotal, cReqFail, cbTxTotal, cbRxTotal, cReadReq, cbReadReqTotal, cbReadRspTotal;
    DWORD dwRttMaxMs;
    EnterCriticalSection(&g_LeechRpcClientPerf.Lock);
    if(!g_LeechRpcClientPerf.fStarted) {
        LeaveCriticalSection(&g_LeechRpcClientPerf.Lock);
        return;
    }
    qwNow = GetTickCount64();
    if(!fForce && g_LeechRpcClientPerf.qwLastLogTickCount64 && (qwNow - g_LeechRpcClientPerf.qwLastLogTickCount64 < LEECHRPC_CLIENT_PERF_LOG_INTERVAL_MS)) {
        LeaveCriticalSection(&g_LeechRpcClientPerf.Lock);
        return;
    }
    g_LeechRpcClientPerf.qwLastLogTickCount64 = qwNow;
    qwElapsedMs = (qwNow > g_LeechRpcClientPerf.qwStartTickCount64) ? (qwNow - g_LeechRpcClientPerf.qwStartTickCount64) : 1;
    if(!qwElapsedMs) { qwElapsedMs = 1; }
    cReqTotal = g_LeechRpcClientPerf.cReqTotal;
    cReqFail = g_LeechRpcClientPerf.cReqFail;
    cbTxTotal = g_LeechRpcClientPerf.cbTxTotal;
    cbRxTotal = g_LeechRpcClientPerf.cbRxTotal;
    cReadReq = g_LeechRpcClientPerf.cReadReq;
    cbReadReqTotal = g_LeechRpcClientPerf.cbReadReqTotal;
    cbReadRspTotal = g_LeechRpcClientPerf.cbReadRspTotal;
    dwRttAvg = g_LeechRpcClientPerf.cRttSamples ? (g_LeechRpcClientPerf.qwRttTotalMs / g_LeechRpcClientPerf.cRttSamples) : 0;
    dwRttMaxMs = g_LeechRpcClientPerf.dwRttMaxMs;
    LeaveCriticalSection(&g_LeechRpcClientPerf.Lock);
    cReqPerSec = (cReqTotal * 1000ULL) / qwElapsedMs;
    cbTxPerSec = (cbTxTotal * 1000ULL) / qwElapsedMs;
    cbRxPerSec = (cbRxTotal * 1000ULL) / qwElapsedMs;
    LeechRPC_ClientPerfLogFile(
        "CLIENT_RPC_PERF elapsed_ms=%llu req_total=%llu req_fail=%llu tx_bytes=%llu rx_bytes=%llu read_req=%llu read_req_bytes=%llu read_rsp_bytes=%llu rtt_avg_ms=%llu rtt_max_ms=%u req_per_s=%llu tx_Bps=%llu rx_Bps=%llu",
        (unsigned long long)qwElapsedMs,
        (unsigned long long)cReqTotal,
        (unsigned long long)cReqFail,
        (unsigned long long)cbTxTotal,
        (unsigned long long)cbRxTotal,
        (unsigned long long)cReadReq,
        (unsigned long long)cbReadReqTotal,
        (unsigned long long)cbReadRspTotal,
        (unsigned long long)dwRttAvg,
        dwRttMaxMs,
        (unsigned long long)cReqPerSec,
        (unsigned long long)cbTxPerSec,
        (unsigned long long)cbRxPerSec
    );
}
#else
static BOOL LeechRPC_ClientPerfEnsureInitialized()
{
    return FALSE;
}

static VOID LeechRPC_ClientPerfReset()
{
    if(!LeechRPC_ClientPerfEnsureInitialized()) { return; }
}

static VOID LeechRPC_ClientPerfOnRequest(_In_ LEECHRPC_MSGTYPE tpReq, _In_ DWORD cbTx, _In_ DWORD cbRx, _In_ DWORD dwRttMs, _In_ BOOL fSuccess, _In_opt_ PLEECHRPC_MSG_HDR pReq, _In_opt_ PLEECHRPC_MSG_HDR pRsp)
{
    if(!LeechRPC_ClientPerfEnsureInitialized()) { return; }
    UNREFERENCED_PARAMETER(tpReq);
    UNREFERENCED_PARAMETER(cbTx);
    UNREFERENCED_PARAMETER(cbRx);
    UNREFERENCED_PARAMETER(dwRttMs);
    UNREFERENCED_PARAMETER(fSuccess);
    UNREFERENCED_PARAMETER(pReq);
    UNREFERENCED_PARAMETER(pRsp);
}

static VOID LeechRPC_ClientPerfLogSnapshot(_In_ BOOL fForce)
{
    if(!LeechRPC_ClientPerfEnsureInitialized()) { return; }
    UNREFERENCED_PARAMETER(fForce);
}
#endif

#ifdef _WIN32
typedef struct tdLEECHRPC_READSCATTER_REQ_TLS {
    PLEECHRPC_MSG_BIN pMsgReq;
    DWORD cbMsgReq;
} LEECHRPC_READSCATTER_REQ_TLS, *PLEECHRPC_READSCATTER_REQ_TLS;

static INIT_ONCE g_LeechRpcReadScatterReqTlsInitOnce = INIT_ONCE_STATIC_INIT;
static DWORD g_dwLeechRpcReadScatterReqTlsIndex = TLS_OUT_OF_INDEXES;

static BOOL CALLBACK LeechRPC_ReadScatterReqTlsInit(_In_ PINIT_ONCE InitOnce, _In_opt_ PVOID Parameter, _Out_opt_ PVOID *Context)
{
    UNREFERENCED_PARAMETER(InitOnce);
    UNREFERENCED_PARAMETER(Parameter);
    UNREFERENCED_PARAMETER(Context);
    g_dwLeechRpcReadScatterReqTlsIndex = TlsAlloc();
    return g_dwLeechRpcReadScatterReqTlsIndex != TLS_OUT_OF_INDEXES;
}

_Success_(return)
static BOOL LeechRPC_ReadScatterReqEnsureTlsBuffer(_In_ DWORD cbReq, _Out_ PLEECHRPC_MSG_BIN *ppMsgReq)
{
    PLEECHRPC_READSCATTER_REQ_TLS pTls;
    PLEECHRPC_MSG_BIN pMsgReq = NULL;
    if(!InitOnceExecuteOnce(&g_LeechRpcReadScatterReqTlsInitOnce, LeechRPC_ReadScatterReqTlsInit, NULL, NULL)) { return FALSE; }
    pTls = (PLEECHRPC_READSCATTER_REQ_TLS)TlsGetValue(g_dwLeechRpcReadScatterReqTlsIndex);
    if(!pTls) {
        if(!(pTls = (PLEECHRPC_READSCATTER_REQ_TLS)LocalAlloc(LMEM_ZEROINIT, sizeof(LEECHRPC_READSCATTER_REQ_TLS)))) { return FALSE; }
        if(!TlsSetValue(g_dwLeechRpcReadScatterReqTlsIndex, pTls)) {
            LocalFree(pTls);
            return FALSE;
        }
    }
    if(pTls->cbMsgReq < cbReq) {
        if(!(pMsgReq = (PLEECHRPC_MSG_BIN)LocalAlloc(0, cbReq))) { return FALSE; }
        LocalFree(pTls->pMsgReq);
        pTls->pMsgReq = pMsgReq;
        pTls->cbMsgReq = cbReq;
    }
    *ppMsgReq = pTls->pMsgReq;
    return TRUE;
}
#else
_Success_(return)
static BOOL LeechRPC_ReadScatterReqEnsureTlsBuffer(_In_ DWORD cbReq, _Out_ PLEECHRPC_MSG_BIN *ppMsgReq)
{
    UNREFERENCED_PARAMETER(cbReq);
    UNREFERENCED_PARAMETER(ppMsgReq);
    return FALSE;
}
#endif

#ifdef _WIN32
static VOID LeechRPC_HttpCloseConnection_NoLock(_Inout_ PLEECHRPC_HTTP_CONN pConn)
{
    SOCKET s = pConn->s;
    pConn->s = INVALID_SOCKET;
    LeechRPC_SecureDestroyConnection_NoLock(pConn);
    if(s != INVALID_SOCKET) {
        shutdown(s, SD_BOTH);
        closesocket(s);
    }
}

static VOID LeechRPC_HttpCloseConnection(_Inout_ PLEECHRPC_HTTP_CONN pConn)
{
    if(!pConn->fLockInitialized) { return; }
    EnterCriticalSection(&pConn->Lock);
    LeechRPC_HttpCloseConnection_NoLock(pConn);
    LeaveCriticalSection(&pConn->Lock);
}

static DWORD LeechRPC_HttpPoolNormalizeSize(_In_ DWORD cRequested)
{
    if(cRequested == 0) {
        cRequested = LEECHRPC_HTTP_POOL_SIZE_DEFAULT;
    }
    if(cRequested > LEECHRPC_HTTP_CONN_POOL_SIZE) {
        cRequested = LEECHRPC_HTTP_CONN_POOL_SIZE;
    }
    return cRequested;
}

static BOOL LeechRPC_SocketSendAll(_In_ SOCKET s, _In_reads_bytes_(cbData) const BYTE *pbData, _In_ DWORD cbData)
{
    DWORD cbSentTotal = 0;
    while(cbSentTotal < cbData) {
        WSABUF wsaBuf;
        DWORD cbSent = 0;
        wsaBuf.buf = (CHAR*)pbData + cbSentTotal;
        wsaBuf.len = cbData - cbSentTotal;
        if(WSASend(s, &wsaBuf, 1, &cbSent, 0, NULL, NULL) == SOCKET_ERROR || cbSent == 0) {
            return FALSE;
        }
        cbSentTotal += cbSent;
    }
    return TRUE;
}

static BOOL LeechRPC_SocketRecvAll(_In_ SOCKET s, _Out_writes_bytes_(cbData) BYTE *pbData, _In_ DWORD cbData)
{
    DWORD cbRecvTotal = 0;
    while(cbRecvTotal < cbData) {
        WSABUF wsaBuf;
        DWORD cbRecv = 0;
        DWORD dwFlags = 0;
        wsaBuf.buf = (CHAR*)pbData + cbRecvTotal;
        wsaBuf.len = cbData - cbRecvTotal;
        if(WSARecv(s, &wsaBuf, 1, &cbRecv, &dwFlags, NULL, NULL) == SOCKET_ERROR || cbRecv == 0) {
            return FALSE;
        }
        cbRecvTotal += cbRecv;
    }
    return TRUE;
}

static BOOL LeechRPC_HttpConnectSocket(
    _In_ PLEECHRPC_CLIENT_CONTEXT ctx,
    _In_z_ LPCSTR szPort,
    _Out_ SOCKET *ps)
{
    struct addrinfo hints = { 0 };
    struct addrinfo *pAddrInfo = NULL, *pAddr = NULL;
    SOCKET s = INVALID_SOCKET;
    DWORD dwTimeoutMs = 15000;
    BOOL fTcpNoDelay = TRUE;
    BOOL fKeepAlive = TRUE;
    INT cbSockBuf = LEECHRPC_SOCKET_BUFFER_SIZE;
    Util_LogFileA("RIVERCLIENT_TCP: connect begin host=%s port=%s", ctx->szHttpHost, szPort);
    *ps = INVALID_SOCKET;
    ctx->dwHttpLastWsaError = 0;
    ctx->iHttpLastGaiError = 0;
    if(!ctx->fHttpSocketApiInitialized) {
        WSADATA wsa = { 0 };
        if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            ctx->dwHttpLastWsaError = WSAGetLastError();
            return FALSE;
        }
        ctx->fHttpSocketApiInitialized = TRUE;
    }
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    ctx->iHttpLastGaiError = getaddrinfo(ctx->szHttpHost, szPort, &hints, &pAddrInfo);
    if(ctx->iHttpLastGaiError != 0) {
        Util_LogFileA("RIVERCLIENT_TCP: connect resolve failed host=%s port=%s gai=%d", ctx->szHttpHost, szPort, ctx->iHttpLastGaiError);
        return FALSE;
    }
    for(pAddr = pAddrInfo; pAddr; pAddr = pAddr->ai_next) {
        s = socket(pAddr->ai_family, pAddr->ai_socktype, pAddr->ai_protocol);
        if(s == INVALID_SOCKET) {
            ctx->dwHttpLastWsaError = WSAGetLastError();
            continue;
        }
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&fTcpNoDelay, sizeof(fTcpNoDelay));
        setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (const char*)&fKeepAlive, sizeof(fKeepAlive));
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&dwTimeoutMs, sizeof(dwTimeoutMs));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&dwTimeoutMs, sizeof(dwTimeoutMs));
        setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char*)&cbSockBuf, sizeof(cbSockBuf));
        setsockopt(s, SOL_SOCKET, SO_SNDBUF, (const char*)&cbSockBuf, sizeof(cbSockBuf));
        if(connect(s, pAddr->ai_addr, (INT)pAddr->ai_addrlen) == 0) {
            *ps = s;
            s = INVALID_SOCKET;
            ctx->dwHttpLastWsaError = 0;
            Util_LogFileA("RIVERCLIENT_TCP: connect success host=%s port=%s", ctx->szHttpHost, szPort);
            break;
        }
        ctx->dwHttpLastWsaError = WSAGetLastError();
        Util_LogFileA("RIVERCLIENT_TCP: connect attempt failed host=%s port=%s wsa=%u", ctx->szHttpHost, szPort, ctx->dwHttpLastWsaError);
        closesocket(s);
        s = INVALID_SOCKET;
    }
    freeaddrinfo(pAddrInfo);
    if(*ps == INVALID_SOCKET) {
        Util_LogFileA("RIVERCLIENT_TCP: connect final failure host=%s port=%s gai=%d wsa=%u", ctx->szHttpHost, szPort, ctx->iHttpLastGaiError, ctx->dwHttpLastWsaError);
    }
    return *ps != INVALID_SOCKET;
}

static VOID LeechRPC_HttpInvalidateSession_NoLock(_Inout_ PLEECHRPC_CLIENT_CONTEXT ctx)
{
    ctx->fHttpSessionReady = FALSE;
    ctx->dwHttpSessionPort = 0;
    ctx->dwHttpSessionTtlMs = 0;
    SecureZeroMemory(ctx->rgbHttpSessionToken, sizeof(ctx->rgbHttpSessionToken));
}

static VOID LeechRPC_HttpInvalidateSession(_Inout_ PLEECHRPC_CLIENT_CONTEXT ctx)
{
    if(!ctx->fHttpBootstrapLockInitialized) { return; }
    EnterCriticalSection(&ctx->HttpBootstrapLock);
    LeechRPC_HttpInvalidateSession_NoLock(ctx);
    LeaveCriticalSection(&ctx->HttpBootstrapLock);
}

static BOOL LeechRPC_HttpBootstrapSession_NoLock(_Inout_ PLEECHRPC_CLIENT_CONTEXT ctx)
{
    LEECHRPC_HTTP_CONN Conn = { 0 };
    PLEECHRPC_MSG_REDIRECT pRedirectRsp = NULL;
    PBYTE pbRedirectRsp = NULL;
    DWORD cbRedirectRsp = 0;
    DWORD dwBootstrapPort;
    CHAR szBootstrapPort[16];
    SOCKET sBootstrap = INVALID_SOCKET;
    ctx->dwHttpLastWsaError = 0;
    ctx->iHttpLastGaiError = 0;
    LeechRPC_HttpInvalidateSession_NoLock(ctx);
    dwBootstrapPort = LeechRPC_HttpGetDefaultBootstrapPort();
    _snprintf_s(szBootstrapPort, sizeof(szBootstrapPort), _TRUNCATE, "%u", dwBootstrapPort);
    Util_LogFileA("RIVERCLIENT_TCP: bootstrap begin host=%s selected_port=%s configured_port=%s", ctx->szHttpHost, szBootstrapPort, ctx->szHttpPort[0] ? ctx->szHttpPort : "(default)");
    if(!LeechRPC_HttpConnectSocket(ctx, ctx->szHttpPort[0] ? ctx->szHttpPort : szBootstrapPort, &sBootstrap)) {
        Util_LogFileA("RIVERCLIENT_TCP: bootstrap connect failed host=%s port=%s", ctx->szHttpHost, ctx->szHttpPort[0] ? ctx->szHttpPort : szBootstrapPort);
        return FALSE;
    }
    Conn.s = sBootstrap;
    if(!LeechRPC_SecureHandshake_NoLock(&Conn)) {
        Util_LogFileA("RIVERCLIENT_TCP: bootstrap secure handshake failed");
        LeechRPC_HttpCloseConnection_NoLock(&Conn);
        return FALSE;
    }
    if(!LeechRPC_SecureRecvMessage_NoLock(&Conn, &pbRedirectRsp, &cbRedirectRsp)) {
        Util_LogFileA("RIVERCLIENT_TCP: bootstrap redirect recv failed");
        LeechRPC_HttpCloseConnection_NoLock(&Conn);
        return FALSE;
    }
    pRedirectRsp = (PLEECHRPC_MSG_REDIRECT)pbRedirectRsp;
    if((cbRedirectRsp != sizeof(LEECHRPC_MSG_REDIRECT)) ||
        (pRedirectRsp->dwMagic != LEECHRPC_MSGMAGIC) ||
        (pRedirectRsp->cbMsg != cbRedirectRsp) ||
        (pRedirectRsp->tpMsg != LEECHRPC_MSGTYPE_REDIRECT_PORT_RSP) ||
        !pRedirectRsp->fMsgResult ||
        (pRedirectRsp->dwPort < LEECHRPC_REDIRECT_PORT_MIN) ||
        (pRedirectRsp->dwPort > LEECHRPC_REDIRECT_PORT_MAX)) {
        Util_LogFileA("RIVERCLIENT_TCP: bootstrap redirect invalid cb=%u tp=%u result=%u port=%u", cbRedirectRsp, pRedirectRsp ? pRedirectRsp->tpMsg : 0, pRedirectRsp ? pRedirectRsp->fMsgResult : 0, pRedirectRsp ? pRedirectRsp->dwPort : 0);
        LocalFree(pbRedirectRsp);
        LeechRPC_HttpCloseConnection_NoLock(&Conn);
        return FALSE;
    }
    ctx->dwHttpSessionPort = pRedirectRsp->dwPort;
    ctx->dwHttpSessionTtlMs = pRedirectRsp->dwTtlMs;
    memcpy(ctx->rgbHttpSessionToken, pRedirectRsp->rgbToken, sizeof(ctx->rgbHttpSessionToken));
    ctx->fHttpSessionReady = TRUE;
    Util_LogFileA("RIVERCLIENT_TCP: bootstrap ok session_port=%u ttl_ms=%u", ctx->dwHttpSessionPort, ctx->dwHttpSessionTtlMs);
    LocalFree(pbRedirectRsp);
    LeechRPC_HttpCloseConnection_NoLock(&Conn);
    return TRUE;
}

static BOOL LeechRPC_HttpEnsureSession(_Inout_ PLEECHRPC_CLIENT_CONTEXT ctx)
{
    BOOL fResult;
    if(ctx->fHttpSessionReady) {
        return TRUE;
    }
    if(!ctx->fHttpBootstrapLockInitialized) {
        return FALSE;
    }
    EnterCriticalSection(&ctx->HttpBootstrapLock);
    fResult = ctx->fHttpSessionReady || LeechRPC_HttpBootstrapSession_NoLock(ctx);
    LeaveCriticalSection(&ctx->HttpBootstrapLock);
    return fResult;
}

static BOOL LeechRPC_HttpCopySessionAuth(
    _In_ PLEECHRPC_CLIENT_CONTEXT ctx,
    _Out_ DWORD *pdwPort,
    _Out_ DWORD *pdwTtlMs,
    _Out_writes_bytes_(LEECHRPC_REDIRECT_TOKEN_SIZE) BYTE *pbToken)
{
    BOOL fResult = FALSE;
    if(!ctx->fHttpBootstrapLockInitialized) {
        return FALSE;
    }
    EnterCriticalSection(&ctx->HttpBootstrapLock);
    if(ctx->fHttpSessionReady && ctx->dwHttpSessionPort) {
        *pdwPort = ctx->dwHttpSessionPort;
        *pdwTtlMs = ctx->dwHttpSessionTtlMs;
        memcpy(pbToken, ctx->rgbHttpSessionToken, LEECHRPC_REDIRECT_TOKEN_SIZE);
        fResult = TRUE;
    }
    LeaveCriticalSection(&ctx->HttpBootstrapLock);
    return fResult;
}

static BOOL LeechRPC_HttpConnectSession_NoLock(_Inout_ PLEECHRPC_CLIENT_CONTEXT ctx, _Inout_ PLEECHRPC_HTTP_CONN pConn)
{
    LEECHRPC_MSG_REDIRECT RedirectReq = { 0 };
    PLEECHRPC_MSG_REDIRECT pRedirectRsp = NULL;
    PBYTE pbRedirectRsp = NULL;
    CHAR szRedirectPort[6] = { 0 };
    BYTE rgbToken[LEECHRPC_REDIRECT_TOKEN_SIZE];
    DWORD dwPort = 0;
    DWORD dwTtlMs = 0;
    DWORD cbRedirectRsp = 0;
    SOCKET sRedirect = INVALID_SOCKET;
    if(!LeechRPC_HttpCopySessionAuth(ctx, &dwPort, &dwTtlMs, rgbToken)) {
        Util_LogFileA("RIVERCLIENT_TCP: session connect missing session auth");
        return FALSE;
    }
    _itoa_s((int)dwPort, szRedirectPort, _countof(szRedirectPort), 10);
    Util_LogFileA("RIVERCLIENT_TCP: session connect begin data_port=%s ttl_ms=%u", szRedirectPort, dwTtlMs);
    if(!LeechRPC_HttpConnectSocket(ctx, szRedirectPort, &sRedirect)) {
        Util_LogFileA("RIVERCLIENT_TCP: session connect socket failed data_port=%s", szRedirectPort);
        SecureZeroMemory(rgbToken, sizeof(rgbToken));
        return FALSE;
    }
    pConn->s = sRedirect;
    sRedirect = INVALID_SOCKET;
    if(!LeechRPC_SecureHandshake_NoLock(pConn)) {
        Util_LogFileA("RIVERCLIENT_TCP: session secure handshake failed data_port=%s", szRedirectPort);
        goto fail;
    }
    RedirectReq.dwMagic = LEECHRPC_MSGMAGIC;
    RedirectReq.cbMsg = sizeof(RedirectReq);
    RedirectReq.tpMsg = LEECHRPC_MSGTYPE_REDIRECT_AUTH_REQ;
    RedirectReq.fMsgResult = TRUE;
    RedirectReq.dwPort = dwPort;
    RedirectReq.dwTtlMs = dwTtlMs;
    memcpy(RedirectReq.rgbToken, rgbToken, sizeof(RedirectReq.rgbToken));
    if(!LeechRPC_SecureSendMessage_NoLock(pConn, (PBYTE)&RedirectReq, sizeof(RedirectReq))) {
        Util_LogFileA("RIVERCLIENT_TCP: session auth request send failed data_port=%s", szRedirectPort);
        goto fail;
    }
    if(!LeechRPC_SecureRecvMessage_NoLock(pConn, &pbRedirectRsp, &cbRedirectRsp)) {
        Util_LogFileA("RIVERCLIENT_TCP: session auth response recv failed data_port=%s", szRedirectPort);
        goto fail;
    }
    pRedirectRsp = (PLEECHRPC_MSG_REDIRECT)pbRedirectRsp;
    if((cbRedirectRsp != sizeof(LEECHRPC_MSG_REDIRECT)) ||
        (pRedirectRsp->dwMagic != LEECHRPC_MSGMAGIC) ||
        (pRedirectRsp->cbMsg != cbRedirectRsp) ||
        (pRedirectRsp->tpMsg != LEECHRPC_MSGTYPE_REDIRECT_AUTH_RSP) ||
        !pRedirectRsp->fMsgResult ||
        (pRedirectRsp->dwPort != dwPort) ||
        memcmp(pRedirectRsp->rgbToken, rgbToken, sizeof(rgbToken))) {
        Util_LogFileA("RIVERCLIENT_TCP: session auth invalid cb=%u tp=%u result=%u rsp_port=%u expected_port=%u", cbRedirectRsp, pRedirectRsp ? pRedirectRsp->tpMsg : 0, pRedirectRsp ? pRedirectRsp->fMsgResult : 0, pRedirectRsp ? pRedirectRsp->dwPort : 0, dwPort);
        goto fail;
    }
    LocalFree(pbRedirectRsp);
    SecureZeroMemory(rgbToken, sizeof(rgbToken));
    Util_LogFileA("RIVERCLIENT_TCP: session connect ok data_port=%s", szRedirectPort);
    return TRUE;
fail:
    if(pbRedirectRsp) { LocalFree(pbRedirectRsp); }
    SecureZeroMemory(rgbToken, sizeof(rgbToken));
    Util_LogFileA("RIVERCLIENT_TCP: session connect failed data_port=%s", szRedirectPort);
    LeechRPC_HttpCloseConnection_NoLock(pConn);
    return FALSE;
}

_Success_(return)
static BOOL LeechRPC_HttpEnsureConnection_NoLock(_In_ PLEECHRPC_CLIENT_CONTEXT ctx, _Inout_ PLEECHRPC_HTTP_CONN pConn)
{
    if(pConn->s != INVALID_SOCKET) {
        return TRUE;
    }
    if(!LeechRPC_HttpEnsureSession(ctx)) {
        return FALSE;
    }
    if(LeechRPC_HttpConnectSession_NoLock(ctx, pConn)) {
        return TRUE;
    }
    LeechRPC_HttpInvalidateSession(ctx);
    if(!LeechRPC_HttpEnsureSession(ctx)) {
        return FALSE;
    }
    return LeechRPC_HttpConnectSession_NoLock(ctx, pConn);
}

static VOID LeechRPC_HttpReadMuxClose_NoLock(_Inout_ PLEECHRPC_HTTP_READMUX pMux)
{
    if(!pMux) { return; }
    LeechRPC_HttpCloseConnection_NoLock(&pMux->Conn);
    InterlockedExchange(&pMux->fSendInFlight, FALSE);
    if(pMux->pRecvOp) {
        pMux->pRecvOp->fRecvHeader = TRUE;
        pMux->pRecvOp->cbExpected = sizeof(LEECHRPC_SECURE_FRAME_HDR);
        pMux->pRecvOp->cbReceived = 0;
    }
}

static VOID LeechRPC_HttpReadMuxUnlinkQueuedSlot_NoLock(_Inout_ PLEECHRPC_HTTP_READMUX pMux, _Inout_ PLEECHRPC_HTTP_PENDING_SLOT pSlot)
{
    PLEECHRPC_HTTP_PENDING_SLOT pPrev = NULL;
    PLEECHRPC_HTTP_PENDING_SLOT pCur = pMux->pSendHead;
    while(pCur) {
        if(pCur == pSlot) {
            if(pPrev) {
                pPrev->Flink = pCur->Flink;
            } else {
                pMux->pSendHead = pCur->Flink;
            }
            if(pMux->pSendTail == pCur) {
                pMux->pSendTail = pPrev;
            }
            pCur->Flink = NULL;
            pCur->fQueued = FALSE;
            return;
        }
        pPrev = pCur;
        pCur = pCur->Flink;
    }
}

static VOID LeechRPC_HttpReadMuxFailPending(_Inout_ PLEECHRPC_HTTP_READMUX pMux)
{
    DWORD i;
    if(!pMux) { return; }
    EnterCriticalSection(&pMux->LockPending);
    pMux->pSendHead = NULL;
    pMux->pSendTail = NULL;
    ZeroMemory(pMux->PendingMap, sizeof(pMux->PendingMap));
    for(i = 0; i < pMux->cPendingMax; i++) {
        if(pMux->Pending[i].fInUse) {
            if(pMux->Pending[i].pbRequest) {
                LocalFree(pMux->Pending[i].pbRequest);
                pMux->Pending[i].pbRequest = NULL;
            }
            pMux->Pending[i].cbRequest = 0;
            if(pMux->Pending[i].pbFrame) {
                LocalFree(pMux->Pending[i].pbFrame);
                pMux->Pending[i].pbFrame = NULL;
            }
            pMux->Pending[i].cbFrame = 0;
            pMux->Pending[i].cbSent = 0;
            pMux->Pending[i].fQueued = FALSE;
            pMux->Pending[i].HashNext = NULL;
            pMux->Pending[i].Flink = NULL;
            pMux->Pending[i].fSuccess = FALSE;
            SetEvent(pMux->Pending[i].hEvent);
        }
    }
    LeaveCriticalSection(&pMux->LockPending);
    InterlockedExchange(&pMux->fSendInFlight, FALSE);
}

static BOOL LeechRPC_HttpReadMuxQueuePendingSlot(
    _Inout_ PLEECHRPC_HTTP_READMUX pMux,
    _Inout_ PLEECHRPC_HTTP_PENDING_SLOT pSlot,
    _In_reads_bytes_(cbRequest) PBYTE pbRequest,
    _In_ DWORD cbRequest)
{
    pSlot->pbRequest = (PBYTE)LocalAlloc(0, cbRequest);
    if(!pSlot->pbRequest) {
        return FALSE;
    }
    memcpy(pSlot->pbRequest, pbRequest, cbRequest);
    pSlot->cbRequest = cbRequest;
    EnterCriticalSection(&pMux->LockPending);
    if(!pSlot->fInUse) {
        LeaveCriticalSection(&pMux->LockPending);
        LocalFree(pSlot->pbRequest);
        pSlot->pbRequest = NULL;
        pSlot->cbRequest = 0;
        return FALSE;
    }
    pSlot->fQueued = TRUE;
    pSlot->Flink = NULL;
    if(pMux->pSendTail) {
        pMux->pSendTail->Flink = pSlot;
    } else {
        pMux->pSendHead = pSlot;
    }
    pMux->pSendTail = pSlot;
    LeaveCriticalSection(&pMux->LockPending);
    return TRUE;
}

static BOOL LeechRPC_HttpReadMuxPostRecv_NoLock(_Inout_ PLEECHRPC_HTTP_READMUX pMux)
{
    WSABUF WsaBuf;
    DWORD dwFlags = 0;
    DWORD cbRecv = 0;
    int wsaResult;
    if(!pMux->pRecvOp || (pMux->Conn.s == INVALID_SOCKET)) {
        return FALSE;
    }
    WsaBuf.buf = pMux->pRecvOp->fRecvHeader
        ? (CHAR*)pMux->pRecvOp->rgbHdr + pMux->pRecvOp->cbReceived
        : (CHAR*)pMux->pRecvOp->pbPayload + pMux->pRecvOp->cbReceived;
    WsaBuf.len = pMux->pRecvOp->cbExpected - pMux->pRecvOp->cbReceived;
    ZeroMemory(&pMux->pRecvOp->Ov, sizeof(pMux->pRecvOp->Ov));
    wsaResult = WSARecv(pMux->Conn.s, &WsaBuf, 1, &cbRecv, &dwFlags, &pMux->pRecvOp->Ov, NULL);
    if((wsaResult == SOCKET_ERROR) && (WSAGetLastError() != WSA_IO_PENDING)) {
        return FALSE;
    }
    return TRUE;
}

static BOOL LeechRPC_HttpReadMuxKickSend(_Inout_ PLEECHRPC_HTTP_READMUX pMux)
{
    PLEECHRPC_HTTP_PENDING_SLOT pSlot;
    DWORD cbSent = 0;
    int wsaResult;
    WSABUF WsaBuf;
    EnterCriticalSection(&pMux->Conn.Lock);
    if((pMux->Conn.s == INVALID_SOCKET) || pMux->fStopThread) {
        LeaveCriticalSection(&pMux->Conn.Lock);
        return FALSE;
    }
    EnterCriticalSection(&pMux->LockPending);
    if(InterlockedCompareExchange(&pMux->fSendInFlight, TRUE, FALSE)) {
        LeaveCriticalSection(&pMux->LockPending);
        LeaveCriticalSection(&pMux->Conn.Lock);
        return TRUE;
    }
    pSlot = pMux->pSendHead;
    if(!pSlot || !pSlot->fInUse || !pSlot->pbRequest || !pSlot->cbRequest) {
        InterlockedExchange(&pMux->fSendInFlight, FALSE);
        LeaveCriticalSection(&pMux->LockPending);
        LeaveCriticalSection(&pMux->Conn.Lock);
        return TRUE;
    }
    if(!pSlot->pbFrame) {
        if(!LeechRPC_SecureBuildMessageFrameAlloc_NoLock(&pMux->Conn, pSlot->pbRequest, pSlot->cbRequest, &pSlot->pbFrame, &pSlot->cbFrame)) {
            InterlockedExchange(&pMux->fSendInFlight, FALSE);
            LeaveCriticalSection(&pMux->LockPending);
            LeaveCriticalSection(&pMux->Conn.Lock);
            return FALSE;
        }
        pSlot->cbSent = 0;
    }
    ZeroMemory(&pMux->SendOp, sizeof(pMux->SendOp));
    pMux->SendOp.dwOpType = LEECHRPC_HTTP_ASYNC_IO_OP_SEND;
    pMux->SendOp.pMux = pMux;
    WsaBuf.buf = (CHAR*)pSlot->pbFrame + pSlot->cbSent;
    WsaBuf.len = pSlot->cbFrame - pSlot->cbSent;
    wsaResult = WSASend(pMux->Conn.s, &WsaBuf, 1, &cbSent, 0, &pMux->SendOp.Ov, NULL);
    if((wsaResult == SOCKET_ERROR) && (WSAGetLastError() != WSA_IO_PENDING)) {
        InterlockedExchange(&pMux->fSendInFlight, FALSE);
        LeaveCriticalSection(&pMux->LockPending);
        LeaveCriticalSection(&pMux->Conn.Lock);
        return FALSE;
    }
    LeaveCriticalSection(&pMux->LockPending);
    LeaveCriticalSection(&pMux->Conn.Lock);
    return TRUE;
}

static BOOL LeechRPC_HttpReadMuxConnect_NoLock(_Inout_ PLEECHRPC_CLIENT_CONTEXT ctx, _Inout_ PLEECHRPC_HTTP_READMUX pMux)
{
    if(pMux->Conn.s != INVALID_SOCKET) {
        return TRUE;
    }
    LeechRPC_HttpReadMuxClose_NoLock(pMux);
    if(!LeechRPC_HttpEnsureSession(ctx)) {
        return FALSE;
    }
    if(!LeechRPC_HttpConnectSession_NoLock(ctx, &pMux->Conn)) {
        LeechRPC_HttpInvalidateSession(ctx);
        if(!LeechRPC_HttpEnsureSession(ctx) || !LeechRPC_HttpConnectSession_NoLock(ctx, &pMux->Conn)) {
            return FALSE;
        }
    }
    if(!CreateIoCompletionPort((HANDLE)pMux->Conn.s, pMux->hIoCp, 0, 0)) {
        LeechRPC_HttpReadMuxClose_NoLock(pMux);
        return FALSE;
    }
    pMux->pRecvOp->fRecvHeader = TRUE;
    pMux->pRecvOp->cbExpected = sizeof(LEECHRPC_SECURE_FRAME_HDR);
    pMux->pRecvOp->cbReceived = 0;
    return LeechRPC_HttpReadMuxPostRecv_NoLock(pMux);
}

static DWORD WINAPI LeechRPC_HttpReadMuxIoWorker(_In_ LPVOID lpParameter)
{
    PLEECHRPC_HTTP_READMUX pMux = (PLEECHRPC_HTTP_READMUX)lpParameter;
    InterlockedExchange(&pMux->fThreadIoRunning, TRUE);
    while(TRUE) {
        DWORD cbTransferred = 0;
        ULONG_PTR ulKey = 0;
        LPOVERLAPPED pOv = NULL;
        PLEECHRPC_HTTP_ASYNC_IO_COMMON pCommon;
        if(!GetQueuedCompletionStatus(pMux->hIoCp, &cbTransferred, &ulKey, &pOv, INFINITE)) {
            if(!pOv) {
                if(pMux->fStopThread) { break; }
                continue;
            }
        }
        if(!pOv) {
            if(pMux->fStopThread) { break; }
            continue;
        }
        pCommon = CONTAINING_RECORD(pOv, LEECHRPC_HTTP_ASYNC_IO_COMMON, Ov);
        if(pCommon->dwOpType == LEECHRPC_HTTP_ASYNC_IO_OP_SEND) {
            BOOL fKickNext = FALSE;
            if((cbTransferred == 0) || pMux->fStopThread) {
                EnterCriticalSection(&pMux->Conn.Lock);
                LeechRPC_HttpReadMuxClose_NoLock(pMux);
                LeaveCriticalSection(&pMux->Conn.Lock);
                LeechRPC_HttpReadMuxFailPending(pMux);
                continue;
            }
            EnterCriticalSection(&pMux->LockPending);
            if(pMux->pSendHead && pMux->pSendHead->fInUse) {
                PLEECHRPC_HTTP_PENDING_SLOT pSlot = pMux->pSendHead;
                pSlot->cbSent += cbTransferred;
                if(pSlot->cbSent >= pSlot->cbFrame) {
                    pMux->pSendHead = pSlot->Flink;
                    if(!pMux->pSendHead) {
                        pMux->pSendTail = NULL;
                    } else {
                        fKickNext = TRUE;
                    }
                    pSlot->Flink = NULL;
                    pSlot->fQueued = FALSE;
                    if(pSlot->pbFrame) {
                        LocalFree(pSlot->pbFrame);
                        pSlot->pbFrame = NULL;
                    }
                    pSlot->cbFrame = 0;
                    pSlot->cbSent = 0;
                    if(pSlot->pbRequest) {
                        LocalFree(pSlot->pbRequest);
                        pSlot->pbRequest = NULL;
                    }
                    pSlot->cbRequest = 0;
                } else {
                    fKickNext = TRUE;
                }
            }
            LeaveCriticalSection(&pMux->LockPending);
            InterlockedExchange(&pMux->fSendInFlight, FALSE);
            if(fKickNext && !LeechRPC_HttpReadMuxKickSend(pMux)) {
                EnterCriticalSection(&pMux->Conn.Lock);
                LeechRPC_HttpReadMuxClose_NoLock(pMux);
                LeaveCriticalSection(&pMux->Conn.Lock);
                LeechRPC_HttpReadMuxFailPending(pMux);
            }
            continue;
        }
        {
            PLEECHRPC_HTTP_ASYNC_RECV_OP pOp = (PLEECHRPC_HTTP_ASYNC_RECV_OP)pCommon;
            PBYTE pbPlain = NULL;
            DWORD cbPlain = 0;
            if((cbTransferred == 0) || pMux->fStopThread) {
                EnterCriticalSection(&pMux->Conn.Lock);
                LeechRPC_HttpReadMuxClose_NoLock(pMux);
                LeaveCriticalSection(&pMux->Conn.Lock);
                LeechRPC_HttpReadMuxFailPending(pMux);
                continue;
            }
            pOp->cbReceived += cbTransferred;
            if(pOp->cbReceived < pOp->cbExpected) {
                EnterCriticalSection(&pMux->Conn.Lock);
                if(!LeechRPC_HttpReadMuxPostRecv_NoLock(pMux)) {
                    LeechRPC_HttpReadMuxClose_NoLock(pMux);
                    LeaveCriticalSection(&pMux->Conn.Lock);
                    LeechRPC_HttpReadMuxFailPending(pMux);
                    continue;
                }
                LeaveCriticalSection(&pMux->Conn.Lock);
                continue;
            }
            if(pOp->fRecvHeader) {
                memcpy(&pOp->Hdr, pOp->rgbHdr, sizeof(pOp->Hdr));
                if((pOp->Hdr.dwMagic != LEECHRPC_SECURE_FRAME_MAGIC) ||
                    (pOp->Hdr.dwVersion != LEECHRPC_SECURE_VERSION) ||
                    (pOp->Hdr.cbFrame < sizeof(LEECHRPC_SECURE_FRAME_HDR) + LEECHRPC_SECURE_TAG_SIZE + sizeof(LEECHRPC_MSG_HDR)) ||
                    (pOp->Hdr.cbFrame >= 0x10000000)) {
                    EnterCriticalSection(&pMux->Conn.Lock);
                    LeechRPC_HttpReadMuxClose_NoLock(pMux);
                    LeaveCriticalSection(&pMux->Conn.Lock);
                    LeechRPC_HttpReadMuxFailPending(pMux);
                    continue;
                }
                pOp->cbExpected = pOp->Hdr.cbFrame - sizeof(LEECHRPC_SECURE_FRAME_HDR);
                pOp->cbReceived = 0;
                pOp->fRecvHeader = FALSE;
                if(pOp->cbPayloadAlloc < pOp->cbExpected) {
                    PBYTE pbNew = (PBYTE)LocalAlloc(LMEM_FIXED, pOp->cbExpected);
                    if(!pbNew) {
                        EnterCriticalSection(&pMux->Conn.Lock);
                        LeechRPC_HttpReadMuxClose_NoLock(pMux);
                        LeaveCriticalSection(&pMux->Conn.Lock);
                        LeechRPC_HttpReadMuxFailPending(pMux);
                        continue;
                    }
                    LocalFree(pOp->pbPayload);
                    pOp->pbPayload = pbNew;
                    pOp->cbPayloadAlloc = pOp->cbExpected;
                }
                EnterCriticalSection(&pMux->Conn.Lock);
                if(!LeechRPC_HttpReadMuxPostRecv_NoLock(pMux)) {
                    LeechRPC_HttpReadMuxClose_NoLock(pMux);
                    LeaveCriticalSection(&pMux->Conn.Lock);
                    LeechRPC_HttpReadMuxFailPending(pMux);
                    continue;
                }
                LeaveCriticalSection(&pMux->Conn.Lock);
                continue;
            }
            EnterCriticalSection(&pMux->Conn.Lock);
            if(!LeechRPC_SecureDecryptReceivedMessage_NoLock(&pMux->Conn, &pOp->Hdr, pOp->pbPayload, pOp->cbExpected, &pbPlain, &cbPlain)) {
                LeechRPC_HttpReadMuxClose_NoLock(pMux);
                LeaveCriticalSection(&pMux->Conn.Lock);
                LeechRPC_HttpReadMuxFailPending(pMux);
                continue;
            }
            pOp->fRecvHeader = TRUE;
            pOp->cbExpected = sizeof(LEECHRPC_SECURE_FRAME_HDR);
            pOp->cbReceived = 0;
            if(!LeechRPC_HttpReadMuxPostRecv_NoLock(pMux)) {
                LeechRPC_HttpReadMuxClose_NoLock(pMux);
                LeaveCriticalSection(&pMux->Conn.Lock);
                LocalFree(pbPlain);
                LeechRPC_HttpReadMuxFailPending(pMux);
                continue;
            }
            LeaveCriticalSection(&pMux->Conn.Lock);
            if((cbPlain >= sizeof(LEECHRPC_MSG_HDR)) && pbPlain) {
                PLEECHRPC_MSG_HDR pRspHdr = (PLEECHRPC_MSG_HDR)pbPlain;
                PLEECHRPC_HTTP_PENDING_SLOT pSlot = NULL;
                EnterCriticalSection(&pMux->LockPending);
                pSlot = LeechRPC_HttpReadMuxPendingFindLocked(pMux, pRspHdr->dwRequestID);
                if(pSlot) {
                    pSlot->pbResponse = pbPlain;
                    pSlot->cbResponse = cbPlain;
                    pSlot->fSuccess = TRUE;
                    SetEvent(pSlot->hEvent);
                    pbPlain = NULL;
                }
                LeaveCriticalSection(&pMux->LockPending);
            }
            if(pbPlain) {
                LocalFree(pbPlain);
            }
        }
    }
    InterlockedExchange(&pMux->fThreadIoRunning, FALSE);
    return 0;
}

static BOOL LeechRPC_IsDataPlaneMsg(_In_ LEECHRPC_MSGTYPE tpMsg)
{
    return (tpMsg == LEECHRPC_MSGTYPE_READSCATTER_REQ);
}

static DWORD LeechRPC_SelectDataMuxIndex(_Inout_ PLEECHRPC_CLIENT_CONTEXT ctx, _In_ DWORD dwRequestID)
{
    UNREFERENCED_PARAMETER(dwRequestID);
    return (DWORD)(InterlockedIncrement(&ctx->iHttpDataMuxNext) % LEECHRPC_HTTP_BULK_MUX_COUNT);
}

static DWORD LeechRPC_HttpReadMuxPendingBucketIndex(_In_ DWORD dwRequestID)
{
    return dwRequestID & (LEECHRPC_HTTP_PENDING_MAP_BUCKETS - 1);
}

static VOID LeechRPC_HttpReadMuxPendingInsertLocked(_Inout_ PLEECHRPC_HTTP_READMUX pMux, _Inout_ PLEECHRPC_HTTP_PENDING_SLOT pSlot)
{
    DWORD iBucket;
    if(!pSlot || !pSlot->dwRequestID) { return; }
    iBucket = LeechRPC_HttpReadMuxPendingBucketIndex(pSlot->dwRequestID);
    pSlot->HashNext = pMux->PendingMap[iBucket];
    pMux->PendingMap[iBucket] = pSlot;
}

static VOID LeechRPC_HttpReadMuxPendingRemoveLocked(_Inout_ PLEECHRPC_HTTP_READMUX pMux, _Inout_ PLEECHRPC_HTTP_PENDING_SLOT pSlot)
{
    DWORD iBucket;
    PLEECHRPC_HTTP_PENDING_SLOT pCur, pPrev = NULL;
    if(!pSlot || !pSlot->dwRequestID) {
        if(pSlot) { pSlot->HashNext = NULL; }
        return;
    }
    iBucket = LeechRPC_HttpReadMuxPendingBucketIndex(pSlot->dwRequestID);
    pCur = pMux->PendingMap[iBucket];
    while(pCur) {
        if(pCur == pSlot) {
            if(pPrev) {
                pPrev->HashNext = pCur->HashNext;
            } else {
                pMux->PendingMap[iBucket] = pCur->HashNext;
            }
            pSlot->HashNext = NULL;
            return;
        }
        pPrev = pCur;
        pCur = pCur->HashNext;
    }
    pSlot->HashNext = NULL;
}

static PLEECHRPC_HTTP_PENDING_SLOT LeechRPC_HttpReadMuxPendingFindLocked(_Inout_ PLEECHRPC_HTTP_READMUX pMux, _In_ DWORD dwRequestID)
{
    PLEECHRPC_HTTP_PENDING_SLOT pCur = pMux->PendingMap[LeechRPC_HttpReadMuxPendingBucketIndex(dwRequestID)];
    while(pCur) {
        if(pCur->fInUse && (pCur->dwRequestID == dwRequestID)) {
            return pCur;
        }
        pCur = pCur->HashNext;
    }
    return NULL;
}

static BOOL LeechRPC_HttpReadMuxEnsureInitializedStorage(
    _Inout_ PLEECHRPC_CLIENT_CONTEXT ctx,
    _Inout_ PVOID *ppStorage,
    _Outptr_ PLEECHRPC_HTTP_READMUX *ppMux)
{
    PLEECHRPC_HTTP_READMUX pMux = (PLEECHRPC_HTTP_READMUX)(*ppStorage);
    DWORD i;
    *ppMux = NULL;
    if(!pMux) {
        pMux = (PLEECHRPC_HTTP_READMUX)LocalAlloc(LMEM_ZEROINIT, sizeof(LEECHRPC_HTTP_READMUX));
        if(!pMux) {
            return FALSE;
        }
        pMux->ctx = ctx;
        pMux->Conn.s = INVALID_SOCKET;
        pMux->cPendingMax = max(1U, min(LEECHRPC_HTTP_MUX_MAX_INFLIGHT, LeechRPC_HttpPoolNormalizeSize(ctx->cHttpPoolActive)));
        InitializeCriticalSection(&pMux->Conn.Lock);
        pMux->Conn.fLockInitialized = TRUE;
        InitializeCriticalSection(&pMux->LockPending);
        pMux->hPendingSlots = CreateSemaphore(NULL, pMux->cPendingMax, pMux->cPendingMax, NULL);
        pMux->hIoCp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
        pMux->pRecvOp = (PLEECHRPC_HTTP_ASYNC_RECV_OP)LocalAlloc(LMEM_ZEROINIT, sizeof(LEECHRPC_HTTP_ASYNC_RECV_OP));
        if(!pMux->hPendingSlots || !pMux->hIoCp || !pMux->pRecvOp) {
            if(pMux->pRecvOp) {
                LocalFree(pMux->pRecvOp);
            }
            if(pMux->hIoCp) {
                CloseHandle(pMux->hIoCp);
            }
            if(pMux->hPendingSlots) {
                CloseHandle(pMux->hPendingSlots);
            }
            DeleteCriticalSection(&pMux->LockPending);
            DeleteCriticalSection(&pMux->Conn.Lock);
            LocalFree(pMux);
            return FALSE;
        }
        for(i = 0; i < pMux->cPendingMax; i++) {
            pMux->Pending[i].hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
            if(!pMux->Pending[i].hEvent) {
                while(i--) {
                    CloseHandle(pMux->Pending[i].hEvent);
                    pMux->Pending[i].hEvent = NULL;
                }
                CloseHandle(pMux->hPendingSlots);
                LocalFree(pMux->pRecvOp);
                CloseHandle(pMux->hIoCp);
                DeleteCriticalSection(&pMux->LockPending);
                DeleteCriticalSection(&pMux->Conn.Lock);
                LocalFree(pMux);
                return FALSE;
            }
        }
        pMux->pRecvOp->dwOpType = LEECHRPC_HTTP_ASYNC_IO_OP_RECV;
        pMux->pRecvOp->pMux = pMux;
        pMux->pRecvOp->fRecvHeader = TRUE;
        pMux->pRecvOp->cbExpected = sizeof(LEECHRPC_SECURE_FRAME_HDR);
        pMux->hThreadIo = CreateThread(NULL, 0, LeechRPC_HttpReadMuxIoWorker, pMux, 0, NULL);
        if(!pMux->hThreadIo) {
            for(i = 0; i < pMux->cPendingMax; i++) {
                CloseHandle(pMux->Pending[i].hEvent);
                pMux->Pending[i].hEvent = NULL;
            }
            CloseHandle(pMux->hPendingSlots);
            LocalFree(pMux->pRecvOp);
            CloseHandle(pMux->hIoCp);
            DeleteCriticalSection(&pMux->LockPending);
            DeleteCriticalSection(&pMux->Conn.Lock);
            LocalFree(pMux);
            return FALSE;
        }
        *ppStorage = pMux;
    }
    *ppMux = pMux;
    return TRUE;
}

static BOOL LeechRPC_HttpReadMuxEnsureInitialized(
    _Inout_ PLEECHRPC_CLIENT_CONTEXT ctx,
    _In_ LEECHRPC_MSGTYPE tpMsg,
    _In_ DWORD dwRequestID,
    _Outptr_ PLEECHRPC_HTTP_READMUX *ppMux)
{
    PVOID *ppStorage;
    if(LeechRPC_IsDataPlaneMsg(tpMsg)) {
        DWORD iMux = LeechRPC_SelectDataMuxIndex(ctx, dwRequestID);
        ppStorage = &ctx->hHttpDataMux[iMux];
    } else {
        ppStorage = &ctx->hHttpControlMux;
    }
    return LeechRPC_HttpReadMuxEnsureInitializedStorage(ctx, ppStorage, ppMux);
}

static PLEECHRPC_HTTP_PENDING_SLOT LeechRPC_HttpReadMuxAcquirePendingSlot(_Inout_ PLEECHRPC_HTTP_READMUX pMux, _In_ DWORD dwWaitMs, _In_ DWORD dwRequestID)
{
    DWORD i;
    PLEECHRPC_HTTP_PENDING_SLOT pSlot = NULL;
    if(WaitForSingleObject(pMux->hPendingSlots, dwWaitMs) != WAIT_OBJECT_0) {
        return NULL;
    }
    EnterCriticalSection(&pMux->LockPending);
    for(i = 0; i < pMux->cPendingMax; i++) {
        if(!pMux->Pending[i].fInUse) {
            pSlot = &pMux->Pending[i];
            pSlot->fInUse = TRUE;
            pSlot->dwRequestID = dwRequestID;
            pSlot->cbRequest = 0;
            pSlot->pbRequest = NULL;
            pSlot->pbFrame = NULL;
            pSlot->cbFrame = 0;
            pSlot->cbSent = 0;
            pSlot->cbResponse = 0;
            pSlot->pbResponse = NULL;
            pSlot->fSuccess = FALSE;
            pSlot->fQueued = FALSE;
            pSlot->HashNext = NULL;
            pSlot->Flink = NULL;
            ResetEvent(pSlot->hEvent);
            LeechRPC_HttpReadMuxPendingInsertLocked(pMux, pSlot);
            break;
        }
    }
    LeaveCriticalSection(&pMux->LockPending);
    if(!pSlot) {
        ReleaseSemaphore(pMux->hPendingSlots, 1, NULL);
    }
    return pSlot;
}

static VOID LeechRPC_HttpReadMuxAbortPendingSlot(_Inout_ PLEECHRPC_HTTP_READMUX pMux, _Inout_opt_ PLEECHRPC_HTTP_PENDING_SLOT pSlot)
{
    if(!pSlot) { return; }
    EnterCriticalSection(&pMux->LockPending);
    LeechRPC_HttpReadMuxPendingRemoveLocked(pMux, pSlot);
    if(pSlot->fQueued) {
        LeechRPC_HttpReadMuxUnlinkQueuedSlot_NoLock(pMux, pSlot);
    }
    if(pSlot->pbRequest) {
        LocalFree(pSlot->pbRequest);
        pSlot->pbRequest = NULL;
    }
    pSlot->cbRequest = 0;
    if(pSlot->pbFrame) {
        LocalFree(pSlot->pbFrame);
        pSlot->pbFrame = NULL;
    }
    pSlot->cbFrame = 0;
    pSlot->cbSent = 0;
    if(pSlot->pbResponse) {
        LocalFree(pSlot->pbResponse);
        pSlot->pbResponse = NULL;
    }
    pSlot->cbResponse = 0;
    pSlot->fSuccess = FALSE;
    pSlot->dwRequestID = 0;
    pSlot->fInUse = FALSE;
    pSlot->HashNext = NULL;
    pSlot->Flink = NULL;
    ResetEvent(pSlot->hEvent);
    LeaveCriticalSection(&pMux->LockPending);
    ReleaseSemaphore(pMux->hPendingSlots, 1, NULL);
}

static VOID LeechRPC_HttpReadMuxCompletePendingSlot(
    _Inout_ PLEECHRPC_HTTP_READMUX pMux,
    _Inout_ PLEECHRPC_HTTP_PENDING_SLOT pSlot,
    _Out_ PBYTE *ppbResponse,
    _Out_ DWORD *pcbResponse,
    _Out_ BOOL *pfSuccess)
{
    EnterCriticalSection(&pMux->LockPending);
    LeechRPC_HttpReadMuxPendingRemoveLocked(pMux, pSlot);
    if(pSlot->fQueued) {
        LeechRPC_HttpReadMuxUnlinkQueuedSlot_NoLock(pMux, pSlot);
    }
    if(pSlot->pbRequest) {
        LocalFree(pSlot->pbRequest);
        pSlot->pbRequest = NULL;
    }
    pSlot->cbRequest = 0;
    if(pSlot->pbFrame) {
        LocalFree(pSlot->pbFrame);
        pSlot->pbFrame = NULL;
    }
    pSlot->cbFrame = 0;
    pSlot->cbSent = 0;
    *ppbResponse = pSlot->pbResponse;
    *pcbResponse = pSlot->cbResponse;
    *pfSuccess = pSlot->fSuccess;
    pSlot->pbResponse = NULL;
    pSlot->cbResponse = 0;
    pSlot->fSuccess = FALSE;
    pSlot->dwRequestID = 0;
    pSlot->fInUse = FALSE;
    pSlot->HashNext = NULL;
    pSlot->Flink = NULL;
    ResetEvent(pSlot->hEvent);
    LeaveCriticalSection(&pMux->LockPending);
    ReleaseSemaphore(pMux->hPendingSlots, 1, NULL);
}

static BOOL LeechRPC_SubmitCommand_HTTP_ReadMux(
    _In_ PLEECHRPC_CLIENT_CONTEXT ctx,
    _In_reads_bytes_(cbMsgIn) PBYTE pbMsgIn,
    _In_ DWORD cbMsgIn,
    _Out_ PPLEECHRPC_MSG_HDR ppMsgOut,
    _Out_ DWORD *pcbMsgOut)
{
    PLEECHRPC_HTTP_READMUX pMux = NULL;
    PLEECHRPC_HTTP_PENDING_SLOT pSlot;
    PBYTE pbResponse = NULL;
    DWORD cbResponse = 0;
    BOOL fSuccess = FALSE;
    DWORD dwWaitMs = max((DWORD)ctx->dwHttpSessionTtlMs, 15000U);
    PLEECHRPC_MSG_HDR pReqHdr = (PLEECHRPC_MSG_HDR)pbMsgIn;
    *ppMsgOut = NULL;
    *pcbMsgOut = 0;
    if(!LeechRPC_HttpReadMuxEnsureInitialized(ctx, pReqHdr->tpMsg, pReqHdr->dwRequestID, &pMux)) {
        return FALSE;
    }
    pSlot = LeechRPC_HttpReadMuxAcquirePendingSlot(pMux, dwWaitMs, pReqHdr->dwRequestID);
    if(!pSlot) {
        return FALSE;
    }
    EnterCriticalSection(&pMux->Conn.Lock);
    if(!LeechRPC_HttpReadMuxConnect_NoLock(ctx, pMux)) {
        LeaveCriticalSection(&pMux->Conn.Lock);
        LeechRPC_HttpReadMuxAbortPendingSlot(pMux, pSlot);
        return FALSE;
    }
    LeaveCriticalSection(&pMux->Conn.Lock);
    if(!LeechRPC_HttpReadMuxQueuePendingSlot(pMux, pSlot, pbMsgIn, cbMsgIn)) {
        LeechRPC_HttpReadMuxAbortPendingSlot(pMux, pSlot);
        return FALSE;
    }
    if(!LeechRPC_HttpReadMuxKickSend(pMux)) {
        EnterCriticalSection(&pMux->Conn.Lock);
        LeechRPC_HttpReadMuxClose_NoLock(pMux);
        LeaveCriticalSection(&pMux->Conn.Lock);
        LeechRPC_HttpReadMuxFailPending(pMux);
    }
    if(WaitForSingleObject(pSlot->hEvent, dwWaitMs) != WAIT_OBJECT_0) {
        LeechRPC_HttpReadMuxAbortPendingSlot(pMux, pSlot);
        return FALSE;
    }
    LeechRPC_HttpReadMuxCompletePendingSlot(pMux, pSlot, &pbResponse, &cbResponse, &fSuccess);
    if(!fSuccess || !pbResponse) {
        LocalFree(pbResponse);
        return FALSE;
    }
    *ppMsgOut = (PLEECHRPC_MSG_HDR)pbResponse;
    *pcbMsgOut = cbResponse;
    return TRUE;
}

static BOOL LeechRPC_ShouldRequestCompressedResponse(_In_ LEECHRPC_MSGTYPE tpMsg)
{
    UNREFERENCED_PARAMETER(tpMsg);
    return FALSE;
}

static BOOL LeechRPC_ShouldCompressRequest(_In_ PLC_CONTEXT ctxLC, _In_ PLEECHRPC_MSG_HDR pMsgIn)
{
    UNREFERENCED_PARAMETER(ctxLC);
    UNREFERENCED_PARAMETER(pMsgIn);
    return FALSE;
}

static
_Success_(return)
BOOL LeechRPC_SubmitCommand_HTTP_Mux(
    _In_ PLEECHRPC_CLIENT_CONTEXT ctx,
    _In_reads_bytes_(cbMsgIn) PBYTE pbMsgIn,
    _In_ DWORD cbMsgIn,
    _Out_ PPLEECHRPC_MSG_HDR ppMsgOut,
    _Out_ DWORD *pcbMsgOut)
{
    return LeechRPC_SubmitCommand_HTTP_ReadMux(ctx, pbMsgIn, cbMsgIn, ppMsgOut, pcbMsgOut);
}
#endif /* _WIN32 */
_Success_(return)
BOOL LeechRPC_SubmitCommand(_In_ PLC_CONTEXT ctxLC, _In_ PLEECHRPC_MSG_HDR pMsgIn, _In_ LEECHRPC_MSGTYPE tpMsgRsp, _Out_ PPLEECHRPC_MSG_HDR ppMsgOut)
{
    PLEECHRPC_CLIENT_CONTEXT ctx = (PLEECHRPC_CLIENT_CONTEXT)ctxLC->hDevice;
#if LEECHRPC_ENABLE_NATIVE_RPC
    error_status_t error;
#endif
    BOOL fOK;
    DWORD cbMsgOut = 0;
    SIZE_T cbMsgOutSize = 0;
    PLEECHRPC_MSG_BIN pMsgOutDecompress = NULL;
    DWORD tmCallStart = GetTickCount();
    DWORD dwCallMs = 0;
    DWORD cbMsgIn = 0;
    // fill out message header given a message type
    pMsgIn->dwMagic = LEECHRPC_MSGMAGIC;
    pMsgIn->fMsgResult = TRUE;
    pMsgIn->dwRequestID = (DWORD)InterlockedIncrement(&ctx->iRequestIdGen);
    switch(pMsgIn->tpMsg) {
        case LEECHRPC_MSGTYPE_PING_REQ:
        case LEECHRPC_MSGTYPE_CLOSE_REQ:
        case LEECHRPC_MSGTYPE_KEEPALIVE_REQ:
        case LEECHRPC_MSGTYPE_PERF_REQ:
            pMsgIn->cbMsg = sizeof(LEECHRPC_MSG_HDR);
            break;
        case LEECHRPC_MSGTYPE_OPEN_REQ:
            pMsgIn->cbMsg = sizeof(LEECHRPC_MSG_OPEN);
            break;
        case LEECHRPC_MSGTYPE_GETOPTION_REQ:
        case LEECHRPC_MSGTYPE_SETOPTION_REQ:
            pMsgIn->cbMsg = sizeof(LEECHRPC_MSG_DATA);
            break;
        case LEECHRPC_MSGTYPE_READSCATTER_REQ:
        case LEECHRPC_MSGTYPE_WRITESCATTER_REQ:
        case LEECHRPC_MSGTYPE_COMMAND_REQ:
            pMsgIn->cbMsg = sizeof(LEECHRPC_MSG_BIN) + ((PLEECHRPC_MSG_BIN)pMsgIn)->cb;
            break;
        default:
            dwCallMs = GetTickCount() - tmCallStart;
            LeechRPC_ClientPerfOnRequest(pMsgIn->tpMsg, cbMsgIn, 0, dwCallMs, FALSE, pMsgIn, NULL);
            LeechRPC_ClientPerfLogSnapshot(FALSE);
            return FALSE;
    }
    // submit message to RPC server:
    cbMsgIn = pMsgIn->cbMsg;
    *ppMsgOut = NULL;
    pMsgIn->dwRpcClientID = ctxLC->Rpc.dwRpcClientId;
    pMsgIn->flags = LeechRPC_ShouldRequestCompressedResponse(pMsgIn->tpMsg) && ctxLC->Rpc.fCompress ? 0 : LEECHRPC_FLAG_NOCOMPRESS;
    if(LeechRPC_ShouldCompressRequest(ctxLC, pMsgIn)) {
        LeechRPC_Compress(&ctx->Compress, (PLEECHRPC_MSG_BIN)pMsgIn, FALSE);
    }
    if(ctx->fIsProtoRpc || ctx->fIsProtoSmb) {
#if LEECHRPC_ENABLE_NATIVE_RPC
        // RPC (over tcp or smb) connection methods:
        error = E_FAIL;
#ifdef _WIN32
        __try {
            error = LeechRpc_ReservedSubmitCommand(ctx->hRPC, pMsgIn->cbMsg, (PBYTE)pMsgIn, &cbMsgOut, (PBYTE*)ppMsgOut);
        } __except(EXCEPTION_EXECUTE_HANDLER) { error = E_FAIL; }
#endif /* _WIN32 */
        if(error) {
            *ppMsgOut = NULL;
            Util_LogFileA("RIVERCLIENT_RPC: submit failed tp=%u req=%u rpc_error=0x%08x", pMsgIn->tpMsg, pMsgIn->dwRequestID, error);
            dwCallMs = GetTickCount() - tmCallStart;
            LeechRPC_ClientPerfOnRequest(pMsgIn->tpMsg, cbMsgIn, 0, dwCallMs, FALSE, pMsgIn, NULL);
            LeechRPC_ClientPerfLogSnapshot(FALSE);
            return FALSE;
        }
#else
        return FALSE;
#endif
    }
    else if(ctx->fIsProtoGRpc) {
        // gRPC (over tcp) connection method:
        fOK = ctx->grpc.hGRPC && ctx->grpc.pfn_leechgrpc_client_submit_command(ctx->grpc.hGRPC, (PBYTE)pMsgIn, pMsgIn->cbMsg, (PBYTE*)ppMsgOut, &cbMsgOutSize);
        if(!fOK) {
            *ppMsgOut = NULL;
            Util_LogFileA("RIVERCLIENT_GRPC: submit failed tp=%u req=%u", pMsgIn->tpMsg, pMsgIn->dwRequestID);
            dwCallMs = GetTickCount() - tmCallStart;
            LeechRPC_ClientPerfOnRequest(pMsgIn->tpMsg, cbMsgIn, 0, dwCallMs, FALSE, pMsgIn, NULL);
            LeechRPC_ClientPerfLogSnapshot(FALSE);
            return FALSE;
        }
        cbMsgOut = (DWORD)cbMsgOutSize;
    }
    else if(ctx->fIsProtoHTTP) {
#ifdef _WIN32
        if(!LeechRPC_SubmitCommand_HTTP_Mux(ctx, (PBYTE)pMsgIn, pMsgIn->cbMsg, ppMsgOut, &cbMsgOut)) {
            *ppMsgOut = NULL;
            Util_LogFileA("RIVERCLIENT_TCP: submit failed tp=%u req=%u", pMsgIn->tpMsg, pMsgIn->dwRequestID);
            dwCallMs = GetTickCount() - tmCallStart;
            LeechRPC_ClientPerfOnRequest(pMsgIn->tpMsg, cbMsgIn, 0, dwCallMs, FALSE, pMsgIn, NULL);
            LeechRPC_ClientPerfLogSnapshot(FALSE);
            return FALSE;
        }
#else
        return FALSE;
#endif
    }
    // sanity check non-trusted incoming message from RPC server.
    fOK = (cbMsgOut >= sizeof(LEECHRPC_MSG_HDR)) && *ppMsgOut && ((*ppMsgOut)->dwMagic == LEECHRPC_MSGMAGIC);
    fOK = fOK && ((*ppMsgOut)->tpMsg <= LEECHRPC_MSGTYPE_MAX) && ((*ppMsgOut)->cbMsg == cbMsgOut) && (cbMsgOut < 0x10000000);
    fOK = fOK && (*ppMsgOut)->fMsgResult && ((*ppMsgOut)->tpMsg == tpMsgRsp);
    fOK = fOK && ((*ppMsgOut)->dwRequestID == pMsgIn->dwRequestID);
    if(fOK) {
        switch((*ppMsgOut)->tpMsg) {
            case LEECHRPC_MSGTYPE_PING_RSP:
            case LEECHRPC_MSGTYPE_CLOSE_RSP:
            case LEECHRPC_MSGTYPE_KEEPALIVE_RSP:
            case LEECHRPC_MSGTYPE_SETOPTION_RSP:
                fOK = (*ppMsgOut)->cbMsg == sizeof(LEECHRPC_MSG_HDR);
                break;
            case LEECHRPC_MSGTYPE_OPEN_RSP:
                fOK = (*ppMsgOut)->cbMsg >= sizeof(LEECHRPC_MSG_OPEN);
                break;
            case LEECHRPC_MSGTYPE_GETOPTION_RSP:
                fOK = (*ppMsgOut)->cbMsg == sizeof(LEECHRPC_MSG_DATA);
                break;
            case LEECHRPC_MSGTYPE_PERF_RSP:
                fOK = (*ppMsgOut)->cbMsg == sizeof(LEECHRPC_MSG_BIN) + ((PLEECHRPC_MSG_BIN)*ppMsgOut)->cb;
                fOK = fOK && (((PLEECHRPC_MSG_BIN)*ppMsgOut)->cb == sizeof(LEECHRPC_PERF_SNAPSHOT));
                break;
            case LEECHRPC_MSGTYPE_READSCATTER_RSP:
            case LEECHRPC_MSGTYPE_WRITESCATTER_RSP:
            case LEECHRPC_MSGTYPE_COMMAND_RSP:
                fOK = (*ppMsgOut)->cbMsg == sizeof(LEECHRPC_MSG_BIN) + ((PLEECHRPC_MSG_BIN)*ppMsgOut)->cb;
                if(fOK && ((PLEECHRPC_MSG_BIN)*ppMsgOut)->cbDecompress) {
                    if(!LeechRPC_Decompress(&ctx->Compress, (PLEECHRPC_MSG_BIN)*ppMsgOut, &pMsgOutDecompress)) { goto fail; }
                    LocalFree(*ppMsgOut);
                    *ppMsgOut = (PLEECHRPC_MSG_HDR)pMsgOutDecompress;
                }
                break;
            default:
                fOK = FALSE;
                break;
        }
        if(!fOK) { goto fail; }
        dwCallMs = GetTickCount() - tmCallStart;
        LeechRPC_ClientPerfOnRequest(pMsgIn->tpMsg, cbMsgIn, cbMsgOut, dwCallMs, TRUE, pMsgIn, *ppMsgOut);
        LeechRPC_ClientPerfLogSnapshot(FALSE);
        return TRUE;
    }
fail:
    Util_LogFileA("RIVERCLIENT_RPC: response validation failed tp=%u req=%u cb_in=%u cb_out=%u", pMsgIn->tpMsg, pMsgIn->dwRequestID, cbMsgIn, cbMsgOut);
    dwCallMs = GetTickCount() - tmCallStart;
    LeechRPC_ClientPerfOnRequest(pMsgIn->tpMsg, cbMsgIn, cbMsgOut, dwCallMs, FALSE, pMsgIn, NULL);
    LeechRPC_ClientPerfLogSnapshot(FALSE);
    LocalFree(*ppMsgOut);
    *ppMsgOut = NULL;
    return FALSE;
}


#if LEECHRPC_CLIENT_PERF_STATS_ENABLE && defined(_WIN32)
static VOID LeechRPC_ClientPerfLogServerSnapshot(_In_ PLC_CONTEXT ctxLC, _In_ BOOL fForce)
{
    LEECHRPC_MSG_HDR MsgReq = { 0 };
    PLEECHRPC_MSG_HDR pMsgRsp = NULL;
    PLEECHRPC_MSG_BIN pRspBin = NULL;
    LEECHRPC_PERF_SNAPSHOT Perf = { 0 };
    LEECHRPC_PERF_SNAPSHOT PerfBase = { 0 };
    QWORD qwNow = 0, qwElapsedMs = 1;
    QWORD cReqTotal = 0, cReqFail = 0, cbInTotal = 0, cbOutTotal = 0, cbReadReqTotal = 0, cbReadRspTotal = 0;
    QWORD cReqPerSec = 0, cbInPerSec = 0, cbOutPerSec = 0;
    DWORD cActiveClients = 0;
    QWORD cActiveRequests = 0, qwOldestConnAgeMs = 0;
    BOOL fBaseJustInitialized = FALSE;
    if(!LeechRPC_ClientPerfEnsureInitialized()) { return; }
    qwNow = GetTickCount64();
    EnterCriticalSection(&g_LeechRpcClientPerf.Lock);
    if(!g_LeechRpcClientPerf.fStarted) {
        LeaveCriticalSection(&g_LeechRpcClientPerf.Lock);
        return;
    }
    if(g_LeechRpcClientPerf.fServerPerfUnsupported) {
        LeaveCriticalSection(&g_LeechRpcClientPerf.Lock);
        return;
    }
    if(!fForce && g_LeechRpcClientPerf.qwServerLastLogTickCount64 && (qwNow - g_LeechRpcClientPerf.qwServerLastLogTickCount64 < LEECHRPC_CLIENT_PERF_LOG_INTERVAL_MS)) {
        LeaveCriticalSection(&g_LeechRpcClientPerf.Lock);
        return;
    }
    g_LeechRpcClientPerf.qwServerLastLogTickCount64 = qwNow;
    LeaveCriticalSection(&g_LeechRpcClientPerf.Lock);

    MsgReq.tpMsg = LEECHRPC_MSGTYPE_PERF_REQ;
    if(!LeechRPC_SubmitCommand(ctxLC, &MsgReq, LEECHRPC_MSGTYPE_PERF_RSP, &pMsgRsp) || !pMsgRsp) {
        EnterCriticalSection(&g_LeechRpcClientPerf.Lock);
        g_LeechRpcClientPerf.fServerPerfUnsupported = TRUE;
        LeaveCriticalSection(&g_LeechRpcClientPerf.Lock);
        LocalFree(pMsgRsp);
        return;
    }
    if(pMsgRsp->cbMsg < sizeof(LEECHRPC_MSG_BIN)) {
        EnterCriticalSection(&g_LeechRpcClientPerf.Lock);
        g_LeechRpcClientPerf.fServerPerfUnsupported = TRUE;
        LeaveCriticalSection(&g_LeechRpcClientPerf.Lock);
        LocalFree(pMsgRsp);
        return;
    }
    pRspBin = (PLEECHRPC_MSG_BIN)pMsgRsp;
    if(pRspBin->cb < sizeof(LEECHRPC_PERF_SNAPSHOT)) {
        EnterCriticalSection(&g_LeechRpcClientPerf.Lock);
        g_LeechRpcClientPerf.fServerPerfUnsupported = TRUE;
        LeaveCriticalSection(&g_LeechRpcClientPerf.Lock);
        LocalFree(pMsgRsp);
        return;
    }
    memcpy(&Perf, pRspBin->pb, sizeof(LEECHRPC_PERF_SNAPSHOT));
    LocalFree(pMsgRsp);

    EnterCriticalSection(&g_LeechRpcClientPerf.Lock);
    if(!g_LeechRpcClientPerf.fServerPerfBaseValid) {
        g_LeechRpcClientPerf.ServerPerfBase = Perf;
        g_LeechRpcClientPerf.fServerPerfBaseValid = TRUE;
        fBaseJustInitialized = TRUE;
    }
    PerfBase = g_LeechRpcClientPerf.ServerPerfBase;
    LeaveCriticalSection(&g_LeechRpcClientPerf.Lock);
    if(fBaseJustInitialized) {
        return;
    }

    if(Perf.qwElapsedMs > PerfBase.qwElapsedMs) {
        qwElapsedMs = Perf.qwElapsedMs - PerfBase.qwElapsedMs;
    }
    if(!qwElapsedMs) { qwElapsedMs = 1; }

    cReqTotal = (Perf.cReqTotal >= PerfBase.cReqTotal) ? (Perf.cReqTotal - PerfBase.cReqTotal) : Perf.cReqTotal;
    cReqFail = (Perf.cReqFail >= PerfBase.cReqFail) ? (Perf.cReqFail - PerfBase.cReqFail) : Perf.cReqFail;
    cbInTotal = (Perf.cbInTotal >= PerfBase.cbInTotal) ? (Perf.cbInTotal - PerfBase.cbInTotal) : Perf.cbInTotal;
    cbOutTotal = (Perf.cbOutTotal >= PerfBase.cbOutTotal) ? (Perf.cbOutTotal - PerfBase.cbOutTotal) : Perf.cbOutTotal;
    cbReadReqTotal = (Perf.cbReadReqTotal >= PerfBase.cbReadReqTotal) ? (Perf.cbReadReqTotal - PerfBase.cbReadReqTotal) : Perf.cbReadReqTotal;
    cbReadRspTotal = (Perf.cbReadRspTotal >= PerfBase.cbReadRspTotal) ? (Perf.cbReadRspTotal - PerfBase.cbReadRspTotal) : Perf.cbReadRspTotal;
    cReqPerSec = (cReqTotal * 1000ULL) / qwElapsedMs;
    cbInPerSec = (cbInTotal * 1000ULL) / qwElapsedMs;
    cbOutPerSec = (cbOutTotal * 1000ULL) / qwElapsedMs;
    cActiveClients = Perf.cActiveClients;
    cActiveRequests = Perf.cActiveRequests;
    qwOldestConnAgeMs = Perf.qwOldestConnAgeMs;

    LeechRPC_ClientPerfLogFile(
        "SERVER_RPC_PERF_CONN_AVG elapsed_ms=%llu req_total=%llu req_fail=%llu in_bytes=%llu out_bytes=%llu read_req_bytes=%llu read_rsp_bytes=%llu active_clients=%u active_req=%llu oldest_conn_ms=%llu req_per_s=%llu in_Bps=%llu out_Bps=%llu",
        (unsigned long long)qwElapsedMs,
        (unsigned long long)cReqTotal,
        (unsigned long long)cReqFail,
        (unsigned long long)cbInTotal,
        (unsigned long long)cbOutTotal,
        (unsigned long long)cbReadReqTotal,
        (unsigned long long)cbReadRspTotal,
        cActiveClients,
        (unsigned long long)cActiveRequests,
        (unsigned long long)qwOldestConnAgeMs,
        (unsigned long long)cReqPerSec,
        (unsigned long long)cbInPerSec,
        (unsigned long long)cbOutPerSec
    );
}
#else
static VOID LeechRPC_ClientPerfLogServerSnapshot(_In_ PLC_CONTEXT ctxLC, _In_ BOOL fForce)
{
    UNREFERENCED_PARAMETER(ctxLC);
    UNREFERENCED_PARAMETER(fForce);
}
#endif
_Success_(return)
BOOL LeechRPC_Ping(_In_ PLC_CONTEXT ctxLC)
{
    BOOL result;
    LEECHRPC_MSG_HDR MsgReq = { 0 };
    PLEECHRPC_MSG_HDR pMsgRsp = NULL;
    MsgReq.tpMsg = LEECHRPC_MSGTYPE_PING_REQ;
    result = LeechRPC_SubmitCommand(ctxLC, &MsgReq, LEECHRPC_MSGTYPE_PING_RSP, &pMsgRsp);
    LocalFree(pMsgRsp);
    return result;
}



//-----------------------------------------------------------------------------
// CLIENT TRACK / KEEPALIVE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID LeechRPC_KeepaliveThreadClient(_In_ PLC_CONTEXT ctxLC)
{
    PLEECHRPC_CLIENT_CONTEXT ctx = (PLEECHRPC_CLIENT_CONTEXT)ctxLC->hDevice;
    LEECHRPC_MSG_HDR MsgReq = { 0 };
    PLEECHRPC_MSG_HDR pMsgRsp = NULL;
    DWORD c = 0;
    ctx->fHousekeeperThread = TRUE;
    ctx->fHousekeeperThreadIsRunning = TRUE;
    while(ctx->fHousekeeperThread) {
        c++;
        if(0 == (c % (10 * 2))) { // send keepalive every 2s
            ZeroMemory(&MsgReq, sizeof(LEECHRPC_MSG_HDR));
            MsgReq.tpMsg = LEECHRPC_MSGTYPE_KEEPALIVE_REQ;
            LeechRPC_SubmitCommand(ctxLC, &MsgReq, LEECHRPC_MSGTYPE_KEEPALIVE_RSP, &pMsgRsp);
            LocalFree(pMsgRsp);
            pMsgRsp = NULL;
        }
        LeechRPC_ClientPerfLogSnapshot(FALSE);
        LeechRPC_ClientPerfLogServerSnapshot(ctxLC, FALSE);
        Sleep(100);
    }
    ctx->fHousekeeperThreadIsRunning = FALSE;
}



//-----------------------------------------------------------------------------
// RPC: OPEN/CLOSE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

static VOID LeechRPC_HttpReadCacheReset();

VOID LeechRPC_RpcClose(PLEECHRPC_CLIENT_CONTEXT ctx)
{
#ifdef _WIN32
    // Close reusable HTTP pool handles:
    if(ctx->fHttpPoolInitialized) {
        DWORD i;
        for(i = 0; i < LEECHRPC_HTTP_CONN_POOL_SIZE; i++) {
            if(ctx->HttpPool[i].fLockInitialized) {
                LeechRPC_HttpCloseConnection(&ctx->HttpPool[i]);
                DeleteCriticalSection(&ctx->HttpPool[i].Lock);
                ctx->HttpPool[i].fLockInitialized = FALSE;
            }
        }
        ctx->cHttpPoolActive = 0;
        ctx->fHttpPoolInitialized = FALSE;
    }
    {
        DWORD iMux;
        for(iMux = 0; iMux < 1 + LEECHRPC_HTTP_BULK_MUX_COUNT; iMux++) {
            PVOID *ppMuxStorage = (iMux == 0) ? &ctx->hHttpControlMux : &ctx->hHttpDataMux[iMux - 1];
            if(*ppMuxStorage) {
                PLEECHRPC_HTTP_READMUX pMux = (PLEECHRPC_HTTP_READMUX)(*ppMuxStorage);
                DWORD i;
                pMux->fStopThread = TRUE;
                if(pMux->hIoCp) {
                    PostQueuedCompletionStatus(pMux->hIoCp, 0, 0, NULL);
                }
                EnterCriticalSection(&pMux->Conn.Lock);
                LeechRPC_HttpReadMuxClose_NoLock(pMux);
                LeaveCriticalSection(&pMux->Conn.Lock);
                if(pMux->hThreadIo) {
                    WaitForSingleObject(pMux->hThreadIo, 2000);
                    CloseHandle(pMux->hThreadIo);
                    pMux->hThreadIo = NULL;
                }
                LeechRPC_HttpReadMuxFailPending(pMux);
                if(pMux->hPendingSlots) {
                    CloseHandle(pMux->hPendingSlots);
                    pMux->hPendingSlots = NULL;
                }
                if(pMux->hIoCp) {
                    CloseHandle(pMux->hIoCp);
                    pMux->hIoCp = NULL;
                }
                if(pMux->pRecvOp) {
                    if(pMux->pRecvOp->pbPayload) {
                        LocalFree(pMux->pRecvOp->pbPayload);
                        pMux->pRecvOp->pbPayload = NULL;
                    }
                    LocalFree(pMux->pRecvOp);
                    pMux->pRecvOp = NULL;
                }
                for(i = 0; i < pMux->cPendingMax; i++) {
                    if(pMux->Pending[i].hEvent) {
                        CloseHandle(pMux->Pending[i].hEvent);
                        pMux->Pending[i].hEvent = NULL;
                    }
                    if(pMux->Pending[i].pbRequest) {
                        LocalFree(pMux->Pending[i].pbRequest);
                        pMux->Pending[i].pbRequest = NULL;
                    }
                    if(pMux->Pending[i].pbFrame) {
                        LocalFree(pMux->Pending[i].pbFrame);
                        pMux->Pending[i].pbFrame = NULL;
                    }
                    if(pMux->Pending[i].pbResponse) {
                        LocalFree(pMux->Pending[i].pbResponse);
                        pMux->Pending[i].pbResponse = NULL;
                    }
                }
                DeleteCriticalSection(&pMux->LockPending);
                if(pMux->Conn.fLockInitialized) {
                    DeleteCriticalSection(&pMux->Conn.Lock);
                    pMux->Conn.fLockInitialized = FALSE;
                }
                LocalFree(pMux);
                *ppMuxStorage = NULL;
            }
        }
    }
    if(ctx->fHttpBootstrapLockInitialized) {
        LeechRPC_HttpInvalidateSession(ctx);
        DeleteCriticalSection(&ctx->HttpBootstrapLock);
        ctx->fHttpBootstrapLockInitialized = FALSE;
    }
    if(ctx->fHttpSocketApiInitialized) {
        WSACleanup();
        ctx->fHttpSocketApiInitialized = FALSE;
    }
#endif /* _WIN32 */
    // Close the gRPC connection:
    if(ctx->grpc.hGRPC) {
        ctx->grpc.pfn_leechgrpc_client_free(ctx->grpc.hGRPC);
        ctx->grpc.hGRPC = NULL;
    }
    if(ctx->grpc.hDll) {
        FreeLibrary(ctx->grpc.hDll);
    }
    ZeroMemory(&ctx->grpc, sizeof(ctx->grpc));
    // Close the MR-RPC connection:
#ifdef _WIN32
#if LEECHRPC_ENABLE_NATIVE_RPC
    if(ctx->hRPC) { 
        RpcBindingFree(ctx->hRPC);
        ctx->hRPC = NULL;
    }
    if(ctx->szStringBinding) {
        RpcStringFreeA(&ctx->szStringBinding);
        ctx->szStringBinding = NULL;
    }
#endif
#endif /* _WIN32 */
}

VOID LeechRPC_Close(_Inout_ PLC_CONTEXT ctxLC)
{
    PLEECHRPC_CLIENT_CONTEXT ctx = (PLEECHRPC_CLIENT_CONTEXT)ctxLC->hDevice;
    LEECHRPC_MSG_HDR Msg = { 0 };
    PLEECHRPC_MSG_HDR pMsgRsp = NULL;
    if(!ctx) { return; }
    ctx->fHousekeeperThread = FALSE;
    Msg.tpMsg = LEECHRPC_MSGTYPE_CLOSE_REQ;
    if(LeechRPC_SubmitCommand(ctxLC, &Msg, LEECHRPC_MSGTYPE_CLOSE_RSP, &pMsgRsp)) {
        LocalFree(pMsgRsp);
    }
    while(ctx->fHousekeeperThreadIsRunning) {
        SwitchToThread();
    }
    LeechRPC_ClientPerfLogSnapshot(TRUE);
    LeechRPC_HttpReadCacheReset();
    LeechRPC_RpcClose(ctx);
    LeechRPC_CompressClose(&ctx->Compress);
    if(ctx->hHousekeeperThread) { CloseHandle(ctx->hHousekeeperThread); }
    LocalFree(ctx);
    ctxLC->hDevice = 0;
}

#ifdef _WIN32

#if LEECHRPC_ENABLE_NATIVE_RPC
/*
* Helper function - connect with custom ntlm credentials to target:
*/
_Success_(return)
BOOL LeechRPC_RpcInitialize_NtlmWithUserCreds(_In_ PLC_CONTEXT ctxLC, _In_ PLEECHRPC_CLIENT_CONTEXT ctx)
{
    BOOL fResult = FALSE;
    RPC_STATUS status;
    WCHAR wszTcpAddr[MAX_PATH];
    WCHAR wszAuthIdentityUser[MAX_PATH] = { 0 };
    WCHAR wszAuthIdentityDomain[MAX_PATH] = { 0 };
    WCHAR wszAuthIdentityPassword[MAX_PATH] = { 0 };
    LPVOID pvAuthBuffer = NULL;
    ULONG cbAuthBuffer = 0;
    ULONG AuthenticationPackage = 0;
    HANDLE LsaHandle = NULL;
    SEC_WINNT_AUTH_IDENTITY_W AuthIdentity = { 0 };
    RPC_SECURITY_QOS RpcSecurityQOS = { 0 };
    LSA_STRING PackageName = { 0 };
    CREDUI_INFOW credui = { 0 };
    RpcSecurityQOS.Version = RPC_C_SECURITY_QOS_VERSION;
    RpcSecurityQOS.Capabilities = RPC_C_QOS_CAPABILITIES_DEFAULT;
    RpcSecurityQOS.IdentityTracking = RPC_C_QOS_IDENTITY_DYNAMIC;
    RpcSecurityQOS.ImpersonationType = RPC_C_IMP_LEVEL_IDENTIFY;
    // prepare ui prompt:
    swprintf_s(wszTcpAddr, _countof(wszTcpAddr), L"Enter your credentials to connect to: %S", ctx->szTcpAddr);
    credui.cbSize = sizeof(credui);
    credui.hwndParent = NULL;
    credui.pszMessageText = wszTcpAddr;
    credui.pszCaptionText = L"Enter network credentials";
    credui.hbmBanner = NULL;
    // get lsa package:
    if(ERROR_SUCCESS != LsaConnectUntrusted(&LsaHandle)) { goto fail; }
    PackageName.Buffer = MICROSOFT_KERBEROS_NAME_A;
    PackageName.Length = (USHORT)strlen(PackageName.Buffer);
    PackageName.MaximumLength = (USHORT)strlen(PackageName.Buffer);
    if(ERROR_SUCCESS != LsaLookupAuthenticationPackage(LsaHandle, &PackageName, &AuthenticationPackage)) { goto fail; }
    // get user creds via credprompt (unless user already set both user & password by command line):
    AuthIdentity.Domain = wszAuthIdentityDomain;
    AuthIdentity.DomainLength = (DWORD)_countof(wszAuthIdentityDomain);
    AuthIdentity.User = wszAuthIdentityUser;
    AuthIdentity.UserLength = (DWORD)_countof(wszAuthIdentityUser);
    AuthIdentity.Password = wszAuthIdentityPassword;
    AuthIdentity.PasswordLength = (DWORD)_countof(wszAuthIdentityPassword);
    AuthIdentity.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
    if(ctx->szAuthNtlmUserInitOnly && ctx->szAuthNtlmPasswordInitOnly) {
        AuthIdentity.DomainLength = 0;
    } else {
        if(ERROR_SUCCESS != CredUIPromptForWindowsCredentialsW(&credui, 0, &AuthenticationPackage, NULL, 0, &pvAuthBuffer, &cbAuthBuffer, NULL, CREDUIWIN_GENERIC)) { goto fail; }
        // unpack user creds:
        if(FALSE == CredUnPackAuthenticationBufferW(CRED_PACK_PROTECTED_CREDENTIALS, pvAuthBuffer, cbAuthBuffer, AuthIdentity.User, &AuthIdentity.UserLength, AuthIdentity.Domain, &AuthIdentity.DomainLength, AuthIdentity.Password, &AuthIdentity.PasswordLength)) { goto fail; }
        if(AuthIdentity.UserLength && (wszAuthIdentityUser[AuthIdentity.UserLength - 1] == 0)) { AuthIdentity.UserLength--; }
        if(AuthIdentity.DomainLength && (wszAuthIdentityDomain[AuthIdentity.DomainLength - 1] == 0)) { AuthIdentity.DomainLength--; }
        if(AuthIdentity.PasswordLength && (wszAuthIdentityPassword[AuthIdentity.PasswordLength - 1] == 0)) { AuthIdentity.PasswordLength--; }
    }
    if(ctx->szAuthNtlmUserInitOnly) {
        AuthIdentity.UserLength = _snwprintf_s(wszAuthIdentityUser, _countof(wszAuthIdentityUser), _TRUNCATE, L"%S", ctx->szAuthNtlmUserInitOnly);
    }
    if(ctx->szAuthNtlmPasswordInitOnly) {
        AuthIdentity.PasswordLength = _snwprintf_s(wszAuthIdentityPassword, _countof(wszAuthIdentityPassword), _TRUNCATE, L"%S", ctx->szAuthNtlmPasswordInitOnly);
    }
    status = RpcBindingSetAuthInfoExW(
        ctx->hRPC,
        NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_AUTHN_WINNT,
        &AuthIdentity,
        RPC_C_AUTHZ_DEFAULT,
        &RpcSecurityQOS);
    if(status) {
        lcprintf(ctxLC, "REMOTE: Failed to set connection security for connection, Error code: 0x%08x\n", status);
        LeechRPC_RpcClose(ctx);
        goto fail;
    }
    fResult = TRUE;
fail:
    SecureZeroMemory(pvAuthBuffer, cbAuthBuffer);
    SecureZeroMemory(wszAuthIdentityPassword, sizeof(wszAuthIdentityPassword));
    if(LsaHandle) { LsaDeregisterLogonProcess(LsaHandle); LsaHandle = NULL; }
    if(pvAuthBuffer) { CoTaskMemFree(pvAuthBuffer); pvAuthBuffer = NULL; }
    return fResult;
}

_Success_(return)
BOOL LeechRPC_RpcInitialize(_In_ PLC_CONTEXT ctxLC, _In_ PLEECHRPC_CLIENT_CONTEXT ctx)
{
    LPSTR szTcpAddr;
    RPC_STATUS status;
    RPC_SECURITY_QOS RpcSecurityQOS = { 0 };
    LeechRPC_RpcClose(ctx);
    // compose binding string:
    if(ctx->fIsProtoSmb) {
        if((ctx->szTcpAddr[0] == 0) || !_stricmp("localhost", ctx->szTcpAddr) || !_stricmp("127.0.0.1", ctx->szTcpAddr)) {
            szTcpAddr = NULL;
        } else {
            szTcpAddr = ctx->szTcpAddr;
        }
        status = RpcStringBindingComposeA(
            CLSID_BINDING_INTERFACE_LEECHRPC,
            "ncacn_np",
            szTcpAddr,
            "\\pipe\\LeechAgent",
            NULL,
            &ctx->szStringBinding);
        if(status) {
            lcprintf(ctxLC, "REMOTE: Failed compose binding: Error code: 0x%08x\n", status);
            LeechRPC_RpcClose(ctx);
            return FALSE;
        }
    }
    if(ctx->fIsProtoRpc) {
        status = RpcStringBindingComposeA(
            CLSID_BINDING_INTERFACE_LEECHRPC,
            "ncacn_ip_tcp",
            ctx->szTcpAddr,
            ctx->szTcpPort,
            NULL,
            &ctx->szStringBinding);
        if(status) {
            lcprintf(ctxLC, "REMOTE: Failed compose binding: Error code: 0x%08x\n", status);
            LeechRPC_RpcClose(ctx);
            return FALSE;
        }
    }
    // create binding:
    status = RpcBindingFromStringBindingA(ctx->szStringBinding, &ctx->hRPC);
    if(status) {
        lcprintf(ctxLC, "REMOTE: Failed create binding: Error code: 0x%08x\n", status);
        LeechRPC_RpcClose(ctx);
        return FALSE;
    }
    // set connection security (if any):
    if(ctx->fIsAuthNTLM) {
        if(ctx->fIsAuthNTLMCredPrompt) {
            if(!LeechRPC_RpcInitialize_NtlmWithUserCreds(ctxLC, ctx)) { return FALSE; }
        } else {
            // NTLM - use default credentials (current user) or user-supplied credentials via prompt:
            RpcSecurityQOS.Version = RPC_C_SECURITY_QOS_VERSION;
            RpcSecurityQOS.Capabilities = RPC_C_QOS_CAPABILITIES_DEFAULT;
            RpcSecurityQOS.IdentityTracking = RPC_C_QOS_IDENTITY_DYNAMIC;
            RpcSecurityQOS.ImpersonationType = RPC_C_IMP_LEVEL_IDENTIFY;
            status = RpcBindingSetAuthInfoExA(
                ctx->hRPC,
                NULL,
                RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                RPC_C_AUTHN_WINNT,
                NULL,
                RPC_C_AUTHZ_DEFAULT,
                &RpcSecurityQOS);
            if(status) {
                lcprintf(ctxLC, "REMOTE: Failed to set connection security for connection, Error code: 0x%08x\n", status);
                LeechRPC_RpcClose(ctx);
                return FALSE;
            }
        }
    }
    if(ctx->fIsAuthKerberos) {
        // Kerberos - use specified SPN for mutual authentication:
        RpcSecurityQOS.Version = RPC_C_SECURITY_QOS_VERSION;
        RpcSecurityQOS.Capabilities = RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH;
        RpcSecurityQOS.IdentityTracking = RPC_C_QOS_IDENTITY_DYNAMIC;
        RpcSecurityQOS.ImpersonationType = RPC_C_IMP_LEVEL_IDENTIFY;
        status = RpcBindingSetAuthInfoExA(
            ctx->hRPC,
            ctx->szRemoteSPN,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_AUTHN_GSS_KERBEROS,
            NULL,
            RPC_C_AUTHZ_NONE,
            &RpcSecurityQOS);
        if(status) {
            lcprintf(ctxLC, "REMOTE: Failed to set connection security: SPN: '%s', Error code: 0x%08x\n", ctx->szRemoteSPN, status);
            lcprintf(ctxLC, "        Maybe try kerberos security disable by specify SPN 'insecure' if server allows...\n");
            LeechRPC_RpcClose(ctx);
            return FALSE;
        }
    }
    lcprintfv_fn(ctxLC, "'%s'\n", ctx->szStringBinding);
    return TRUE;
}

#else
_Success_(return)
BOOL LeechRPC_RpcInitialize(_In_ PLC_CONTEXT ctxLC, _In_ PLEECHRPC_CLIENT_CONTEXT ctx)
{
    (void)ctx;
    lcprintf(ctxLC, "REMOTE: Native MS-RPC transport is disabled at compile time. Use '-remote grpc' or '-remote http'.\n");
    return FALSE;
}
#endif /* LEECHRPC_ENABLE_NATIVE_RPC */

#endif /* _WIN32 */
#if defined(LINUX) || defined(MACOS)

_Success_(return)
BOOL LeechRPC_RpcInitialize(_In_ PLC_CONTEXT ctxLC, _In_ PLEECHRPC_CLIENT_CONTEXT ctx)
{
    lcprintf(ctxLC, "REMOTE: MS-RPC with '-remote rpc' or '-remote smb' is only supported on Windows. gRPC is supported.\n");
    return FALSE;
}

#endif /* LINUX || MACOS */

_Success_(return)
BOOL LeechRPC_GRpcInitialize(_In_ PLC_CONTEXT ctxLC, _In_ PLEECHRPC_CLIENT_CONTEXT ctx)
{
    DWORD dwTcpPort = strtol(ctx->szTcpPort, NULL, 10);
    ctx->grpc.hDll = LoadLibraryA("libleechgrpc"LC_LIBRARY_FILETYPE);
    if(!ctx->grpc.hDll) {
        lcprintf(ctxLC, "REMOTE: Failed to load 'libleechgrpc"LC_LIBRARY_FILETYPE"'\n");
        return FALSE;
    }
    ctx->grpc.pfn_leechgrpc_client_create_insecure = (pfn_leechgrpc_client_create_insecure)GetProcAddress(ctx->grpc.hDll, "leechgrpc_client_create_insecure");
    ctx->grpc.pfn_leechgrpc_client_create_secure_p12 = (pfn_leechgrpc_client_create_secure_p12)GetProcAddress(ctx->grpc.hDll, "leechgrpc_client_create_secure_p12");
    ctx->grpc.pfn_leechgrpc_client_free = (pfn_leechgrpc_client_free)GetProcAddress(ctx->grpc.hDll, "leechgrpc_client_free");
    ctx->grpc.pfn_leechgrpc_client_submit_command = (pfn_leechgrpc_client_submit_command)GetProcAddress(ctx->grpc.hDll, "leechgrpc_client_submit_command");
    if(!ctx->grpc.pfn_leechgrpc_client_create_insecure || !ctx->grpc.pfn_leechgrpc_client_create_secure_p12 || !ctx->grpc.pfn_leechgrpc_client_free || !ctx->grpc.pfn_leechgrpc_client_submit_command) {
        lcprintf(ctxLC, "REMOTE: Failed to load functions from 'libleechgrpc"LC_LIBRARY_FILETYPE"'\n");
        return FALSE;
    }
    if(ctx->fIsAuthInsecure) {
        ctx->grpc.hGRPC = ctx->grpc.pfn_leechgrpc_client_create_insecure(ctx->szTcpAddr, dwTcpPort);
    } else {
        ctx->grpc.hGRPC = ctx->grpc.pfn_leechgrpc_client_create_secure_p12(
            ctx->szTcpAddr,
            dwTcpPort,
            ctx->grpc.szServerCertHostnameOverride[0] ? ctx->grpc.szServerCertHostnameOverride : NULL,
            ctx->grpc.szServerCertCaPath[0] ? ctx->grpc.szServerCertCaPath : NULL,
            ctx->grpc.szClientTlsP12Path,
            ctx->grpc.szClientTlsP12Password);
    }
    if(!ctx->grpc.hGRPC) {
        lcprintf(ctxLC, "REMOTE: Failed to create gRPC client connection\n");
        return FALSE;
    }
    return TRUE;
}




#define LEECHRPC_SCATTER_MAX_MEMS_PER_REQ     0x2000
#define LEECHRPC_SCATTER_MAX_CB_PER_REQ       0x01000000

#ifndef LEECHRPC_HTTP_READ_OPT_ENABLE
#define LEECHRPC_HTTP_READ_OPT_ENABLE         1
#endif

#define LEECHRPC_HTTP_FETCH_PAGE_SIZE                     0x1000
#define LEECHRPC_HTTP_FETCH_MAX_PAGES_PER_REQ             (LEECHRPC_SCATTER_MAX_CB_PER_REQ / LEECHRPC_HTTP_FETCH_PAGE_SIZE)
#define LEECHRPC_HTTP_READ_CACHE_ENTRIES                  4096
#define LEECHRPC_HTTP_READ_CACHE_TTL_MS                   250
#define LEECHRPC_HTTP_PREFETCH_AHEAD_PAGES                8
#define LEECHRPC_HTTP_PREFETCH_EXTRA_RATIO_PERCENT        100
#define LEECHRPC_HTTP_PREFETCH_EXTRA_PAGES_ABSOLUTE_MAX   1024


VOID LeechRPC_ReadScatter_Impl(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    BOOL result = FALSE, fReqFromTls = FALSE;
    DWORD i, cValidMEMs = 0;
    PLEECHRPC_MSG_BIN pMsgReq = NULL;
    PLEECHRPC_MSG_BIN pMsgRsp = NULL;
    DWORD cbOffset, cbTotal = 0;
    DWORD cbReq;
    PMEM_SCATTER pMEM_Src, pMEM_Dst;
    BOOL fPaddedRsp;
    // 0: sanity check incoming data and count valid non-already finished MEMs
    for(i = 0; i < cMEMs; i++) {
        pMEM_Src = ppMEMs[i];
        if((pMEM_Src->version != MEM_SCATTER_VERSION) || (pMEM_Src->cb > 0x1000)) { goto fail; }
        if(!pMEM_Src->f && MEM_SCATTER_ADDR_ISVALID(pMEM_Src)) {
            cValidMEMs++;
        }
    }
    // 1: prepare message to send
    cbReq = sizeof(LEECHRPC_MSG_BIN) + cValidMEMs * sizeof(MEM_SCATTER);
    if(LeechRPC_ReadScatterReqEnsureTlsBuffer(cbReq, &pMsgReq)) {
        ZeroMemory(pMsgReq, cbReq);
        fReqFromTls = TRUE;
    } else {
        if(!(pMsgReq = LocalAlloc(LMEM_ZEROINIT, cbReq))) { return; }
    }
    pMsgReq->tpMsg = LEECHRPC_MSGTYPE_READSCATTER_REQ;
    pMsgReq->cb = cValidMEMs * sizeof(MEM_SCATTER);
    pMEM_Dst = (PMEM_SCATTER)pMsgReq->pb;
    for(i = 0; i < cMEMs; i++) {
        pMEM_Src = ppMEMs[i];
        if(!pMEM_Src->f && MEM_SCATTER_ADDR_ISVALID(pMEM_Src)) {
            cbTotal += pMEM_Src->cb;
            memcpy(pMEM_Dst, pMEM_Src, sizeof(MEM_SCATTER));
            pMEM_Dst = pMEM_Dst + 1;
        }
    }
    Util_LogFileA("RIVERCLIENT_READ: begin mems=%u valid=%u total=%u", cMEMs, cValidMEMs, cbTotal);
    pMsgReq->qwData[0] = cValidMEMs;
    pMsgReq->qwData[1] = cbTotal;
    // 2: transmit & get result
    result = LeechRPC_SubmitCommand(ctxLC, (PLEECHRPC_MSG_HDR)pMsgReq, LEECHRPC_MSGTYPE_READSCATTER_RSP, (PPLEECHRPC_MSG_HDR)&pMsgRsp);
    if(!result) {
        Util_LogFileA("RIVERCLIENT_READ: submit failed mems=%u valid=%u total=%u", cMEMs, cValidMEMs, cbTotal);
        goto fail;
    }
    if((pMsgRsp->qwData[0] != cValidMEMs) || (pMsgRsp->cb < cValidMEMs * sizeof(MEM_SCATTER))) {
        Util_LogFileA("RIVERCLIENT_READ: invalid rsp valid=%u rsp_valid=%llu rsp_cb=%u", cValidMEMs, pMsgRsp->qwData[0], pMsgRsp->cb);
        goto fail;
    }
    fPaddedRsp = (pMsgRsp->flags & LEECHRPC_FLAG_READSCATTER_PADDED) ? TRUE : FALSE;
    cbOffset = cValidMEMs * sizeof(MEM_SCATTER);
    pMEM_Src = (PMEM_SCATTER)pMsgRsp->pb;
    for(i = 0; i < cMEMs; i++) {
        pMEM_Dst = ppMEMs[i];
        if(pMEM_Dst->f || MEM_SCATTER_ADDR_ISINVALID(pMEM_Dst)) { continue; }
        // sanity check
        if((pMEM_Src->version != MEM_SCATTER_VERSION) || (pMEM_Src->qwA != pMEM_Dst->qwA) || (pMEM_Src->cb != pMEM_Dst->cb) || (pMEM_Dst->cb > pMsgRsp->cb - cbOffset)) {
            Util_LogFileA("RIVERCLIENT_READ: scatter mismatch index=%u req_qwA=0x%016llx rsp_qwA=0x%016llx req_cb=%u rsp_cb=%u rsp_payload=%u offset=%u", i, pMEM_Dst->qwA, pMEM_Src->qwA, pMEM_Dst->cb, pMEM_Src->cb, pMsgRsp->cb, cbOffset);
            break;
        }
        pMEM_Dst->f = pMEM_Src->f;
        if(pMEM_Src->f) {
            memcpy(pMEM_Dst->pb, pMsgRsp->pb + cbOffset, pMEM_Dst->cb);
        }
        if(fPaddedRsp || pMEM_Src->f) {
            cbOffset += pMEM_Dst->cb;
        }
        pMEM_Src = pMEM_Src + 1;
    }
    Util_LogFileA("RIVERCLIENT_READ: end mems=%u valid=%u total=%u", cMEMs, cValidMEMs, cbTotal);
fail:
    if(!result) {
        Util_LogFileA("RIVERCLIENT_READ: fail mems=%u valid=%u total=%u", cMEMs, cValidMEMs, cbTotal);
    }
    if(!fReqFromTls) {
        LocalFree(pMsgReq);
    }
    LocalFree(pMsgRsp);
}

VOID LeechRPC_ReadScatter_ChunkedLegacy(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    DWORD cMEMsChunk;
    while(cMEMs) {
        cMEMsChunk = min(cMEMs, (DWORD)LEECHRPC_SCATTER_MAX_MEMS_PER_REQ);
        LeechRPC_ReadScatter_Impl(ctxLC, cMEMsChunk, ppMEMs);
        ppMEMs += cMEMsChunk;
        cMEMs -= cMEMsChunk;
    }
}

#ifdef _WIN32
static DWORD WINAPI LeechRPC_ReadScatterPoolWorker(_In_ LPVOID lpParameter)
{
    UNREFERENCED_PARAMETER(lpParameter);
    while(TRUE) {
        PLEECHRPC_READSCATTER_WORKITEM pWork = NULL;
        WaitForSingleObject(g_hLeechRpcReadScatterPoolSem, INFINITE);
        EnterCriticalSection(&g_LeechRpcReadScatterPoolLock);
        pWork = g_pLeechRpcReadScatterPoolHead;
        if(pWork) {
            g_pLeechRpcReadScatterPoolHead = pWork->Flink;
            if(!g_pLeechRpcReadScatterPoolHead) {
                g_pLeechRpcReadScatterPoolTail = NULL;
            }
        }
        LeaveCriticalSection(&g_LeechRpcReadScatterPoolLock);
        if(!pWork) {
            if(g_fLeechRpcReadScatterPoolStop) {
                break;
            }
            continue;
        }
        LeechRPC_ReadScatter_Impl(pWork->ctxLC, pWork->cMEMs, pWork->ppMEMs);
        if(InterlockedDecrement(&pWork->pBatch->cPending) == 0) {
            SetEvent(pWork->pBatch->hDoneEvent);
        }
        LocalFree(pWork);
    }
    return 0;
}

static BOOL CALLBACK LeechRPC_ReadScatterPoolInit(_In_ PINIT_ONCE InitOnce, _In_opt_ PVOID Parameter, _Out_opt_ PVOID *Context)
{
    DWORD i;
    UNREFERENCED_PARAMETER(InitOnce);
    UNREFERENCED_PARAMETER(Parameter);
    UNREFERENCED_PARAMETER(Context);
    InitializeCriticalSection(&g_LeechRpcReadScatterPoolLock);
    g_hLeechRpcReadScatterPoolSem = CreateSemaphore(NULL, 0, 0x7fffffff, NULL);
    if(!g_hLeechRpcReadScatterPoolSem) {
        DeleteCriticalSection(&g_LeechRpcReadScatterPoolLock);
        return FALSE;
    }
    for(i = 0; i < LEECHRPC_HTTP_READ_PARALLELISM_MAX; i++) {
        g_ahLeechRpcReadScatterPoolWorkers[i] = CreateThread(NULL, 0, LeechRPC_ReadScatterPoolWorker, NULL, 0, NULL);
        if(!g_ahLeechRpcReadScatterPoolWorkers[i]) {
            g_fLeechRpcReadScatterPoolStop = TRUE;
            while(i--) {
                ReleaseSemaphore(g_hLeechRpcReadScatterPoolSem, 1, NULL);
                WaitForSingleObject(g_ahLeechRpcReadScatterPoolWorkers[i], 2000);
                CloseHandle(g_ahLeechRpcReadScatterPoolWorkers[i]);
                g_ahLeechRpcReadScatterPoolWorkers[i] = NULL;
            }
            CloseHandle(g_hLeechRpcReadScatterPoolSem);
            g_hLeechRpcReadScatterPoolSem = NULL;
            DeleteCriticalSection(&g_LeechRpcReadScatterPoolLock);
            g_fLeechRpcReadScatterPoolStop = FALSE;
            return FALSE;
        }
    }
    return TRUE;
}

static BOOL LeechRPC_ReadScatterPoolEnsureInitialized()
{
    return InitOnceExecuteOnce(&g_LeechRpcReadScatterPoolInitOnce, LeechRPC_ReadScatterPoolInit, NULL, NULL) ? TRUE : FALSE;
}

static BOOL LeechRPC_ReadScatterPoolQueue(
    _In_ PLC_CONTEXT ctxLC,
    _In_ DWORD cMEMs,
    _Inout_ PPMEM_SCATTER ppMEMs,
    _Inout_ PLEECHRPC_READSCATTER_BATCH pBatch)
{
    PLEECHRPC_READSCATTER_WORKITEM pWork;
    if(!LeechRPC_ReadScatterPoolEnsureInitialized()) {
        return FALSE;
    }
    pWork = (PLEECHRPC_READSCATTER_WORKITEM)LocalAlloc(LMEM_ZEROINIT, sizeof(LEECHRPC_READSCATTER_WORKITEM));
    if(!pWork) {
        return FALSE;
    }
    pWork->ctxLC = ctxLC;
    pWork->cMEMs = cMEMs;
    pWork->ppMEMs = ppMEMs;
    pWork->pBatch = pBatch;
    InterlockedIncrement(&pBatch->cPending);
    EnterCriticalSection(&g_LeechRpcReadScatterPoolLock);
    if(g_pLeechRpcReadScatterPoolTail) {
        g_pLeechRpcReadScatterPoolTail->Flink = pWork;
    } else {
        g_pLeechRpcReadScatterPoolHead = pWork;
    }
    g_pLeechRpcReadScatterPoolTail = pWork;
    LeaveCriticalSection(&g_LeechRpcReadScatterPoolLock);
    if(!ReleaseSemaphore(g_hLeechRpcReadScatterPoolSem, 1, NULL)) {
        EnterCriticalSection(&g_LeechRpcReadScatterPoolLock);
        if(g_pLeechRpcReadScatterPoolHead == pWork) {
            g_pLeechRpcReadScatterPoolHead = pWork->Flink;
            if(!g_pLeechRpcReadScatterPoolHead) {
                g_pLeechRpcReadScatterPoolTail = NULL;
            }
        } else {
            PLEECHRPC_READSCATTER_WORKITEM pPrev = g_pLeechRpcReadScatterPoolHead;
            while(pPrev && (pPrev->Flink != pWork)) {
                pPrev = pPrev->Flink;
            }
            if(pPrev) {
                pPrev->Flink = pWork->Flink;
                if(g_pLeechRpcReadScatterPoolTail == pWork) {
                    g_pLeechRpcReadScatterPoolTail = pPrev;
                }
            }
        }
        LeaveCriticalSection(&g_LeechRpcReadScatterPoolLock);
        InterlockedDecrement(&pBatch->cPending);
        LocalFree(pWork);
        return FALSE;
    }
    return TRUE;
}

static VOID LeechRPC_ReadScatter_PackedHttpMux(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    DWORD i, cChunk = 0, cValidChunk = 0, cbValidChunk = 0, iChunkBase = 0;
    DWORD iWorker;
    PMEM_SCATTER pMEM;
    PMEM_SCATTER *ppChunkList = NULL;
    PLEECHRPC_READSCATTER_CHUNK pChunks = NULL;
    LEECHRPC_READSCATTER_BATCH Batch = { 0 };
    ppChunkList = (PMEM_SCATTER*)LocalAlloc(LMEM_ZEROINIT, sizeof(PMEM_SCATTER) * cMEMs);
    pChunks = (PLEECHRPC_READSCATTER_CHUNK)LocalAlloc(LMEM_ZEROINIT, sizeof(LEECHRPC_READSCATTER_CHUNK) * cMEMs);
    if(!ppChunkList || !pChunks) {
        LocalFree(ppChunkList);
        LocalFree(pChunks);
        LeechRPC_ReadScatter_ChunkedLegacy(ctxLC, cMEMs, ppMEMs);
        return;
    }
    for(i = 0; i < cMEMs; i++) {
        pMEM = ppMEMs[i];
        if(!pMEM || (pMEM->version != MEM_SCATTER_VERSION) || (pMEM->cb > 0x1000)) {
            LocalFree(ppChunkList);
            LocalFree(pChunks);
            LeechRPC_ReadScatter_ChunkedLegacy(ctxLC, cMEMs, ppMEMs);
            return;
        }
        if(pMEM->f || MEM_SCATTER_ADDR_ISINVALID(pMEM)) { continue; }
        if(cValidChunk && ((cValidChunk >= LEECHRPC_SCATTER_MAX_MEMS_PER_REQ) || (cbValidChunk + pMEM->cb > LEECHRPC_SCATTER_MAX_CB_PER_REQ))) {
            pChunks[cChunk].cMEMs = cValidChunk;
            pChunks[cChunk].ppMEMs = &ppChunkList[iChunkBase];
            iChunkBase += cValidChunk;
            cChunk++;
            cValidChunk = 0;
            cbValidChunk = 0;
        }
        ppChunkList[iChunkBase + cValidChunk] = pMEM;
        cValidChunk++;
        cbValidChunk += pMEM->cb;
    }
    if(cValidChunk) {
        pChunks[cChunk].cMEMs = cValidChunk;
        pChunks[cChunk].ppMEMs = &ppChunkList[iChunkBase];
        cChunk++;
    }
    if(cChunk <= 1) {
        if(cChunk == 1) {
            LeechRPC_ReadScatter_Impl(ctxLC, pChunks[0].cMEMs, pChunks[0].ppMEMs);
        }
        LocalFree(ppChunkList);
        LocalFree(pChunks);
        return;
    }
    Batch.hDoneEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if(!Batch.hDoneEvent) {
        for(iWorker = 0; iWorker < cChunk; iWorker++) {
            LeechRPC_ReadScatter_Impl(ctxLC, pChunks[iWorker].cMEMs, pChunks[iWorker].ppMEMs);
        }
        LocalFree(ppChunkList);
        LocalFree(pChunks);
        return;
    }
    for(iWorker = 0; iWorker < cChunk; iWorker++) {
        if(!LeechRPC_ReadScatterPoolQueue(ctxLC, pChunks[iWorker].cMEMs, pChunks[iWorker].ppMEMs, &Batch)) {
            LeechRPC_ReadScatter_Impl(ctxLC, pChunks[iWorker].cMEMs, pChunks[iWorker].ppMEMs);
        }
    }
    if(InterlockedCompareExchange(&Batch.cPending, 0, 0) > 0) {
        WaitForSingleObject(Batch.hDoneEvent, INFINITE);
    }
    CloseHandle(Batch.hDoneEvent);
    LocalFree(ppChunkList);
    LocalFree(pChunks);
}
#endif

static VOID LeechRPC_ReadScatter_Packed(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    DWORD i;
    DWORD cValidChunk = 0;
    DWORD cbValidChunk = 0;
    PMEM_SCATTER pMEM;
    PMEM_SCATTER pValidChunk[LEECHRPC_SCATTER_MAX_MEMS_PER_REQ];
    if(!cMEMs || !ppMEMs) { return; }
    for(i = 0; i < cMEMs; i++) {
        pMEM = ppMEMs[i];
        if(!pMEM || (pMEM->version != MEM_SCATTER_VERSION) || (pMEM->cb > 0x1000)) {
            LeechRPC_ReadScatter_ChunkedLegacy(ctxLC, cMEMs, ppMEMs);
            return;
        }
    }
#ifdef _WIN32
    if(ctxLC->Config.fRemote && ((PLEECHRPC_CLIENT_CONTEXT)ctxLC->hDevice)->fIsProtoHTTP) {
        LeechRPC_ReadScatter_ChunkedLegacy(ctxLC, cMEMs, ppMEMs);
        return;
    }
#endif
    for(i = 0; i < cMEMs; i++) {
        pMEM = ppMEMs[i];
        if(pMEM->f || MEM_SCATTER_ADDR_ISINVALID(pMEM)) { continue; }
        if(cValidChunk && ((cValidChunk >= LEECHRPC_SCATTER_MAX_MEMS_PER_REQ) || (cbValidChunk + pMEM->cb > LEECHRPC_SCATTER_MAX_CB_PER_REQ))) {
            LeechRPC_ReadScatter_Impl(ctxLC, cValidChunk, pValidChunk);
            cValidChunk = 0;
            cbValidChunk = 0;
        }
        pValidChunk[cValidChunk++] = pMEM;
        cbValidChunk += pMEM->cb;
    }
    if(cValidChunk) {
        LeechRPC_ReadScatter_Impl(ctxLC, cValidChunk, pValidChunk);
    }
}

#if LEECHRPC_HTTP_READ_OPT_ENABLE && defined(_WIN32)
typedef struct tdLEECHRPC_HTTP_READ_CACHE_ENTRY {
    QWORD qwPageBase;
    DWORD dwTickMs;
    BYTE pbPage[LEECHRPC_HTTP_FETCH_PAGE_SIZE];
} LEECHRPC_HTTP_READ_CACHE_ENTRY, *PLEECHRPC_HTTP_READ_CACHE_ENTRY;

typedef struct tdLEECHRPC_HTTP_READ_CACHE {
    BOOL fInitialized;
    CRITICAL_SECTION Lock;
    DWORD cEntries;
    PLEECHRPC_HTTP_READ_CACHE_ENTRY pEntries;
} LEECHRPC_HTTP_READ_CACHE, *PLEECHRPC_HTTP_READ_CACHE;

static LEECHRPC_HTTP_READ_CACHE g_LeechRpcHttpReadCache = { 0 };
static INIT_ONCE g_LeechRpcHttpReadCacheInitOnce = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK LeechRPC_HttpReadCacheInit(_In_ PINIT_ONCE InitOnce, _In_opt_ PVOID Parameter, _Out_opt_ PVOID *Context)
{
    DWORD i;
    PLEECHRPC_HTTP_READ_CACHE_ENTRY pEntries;
    UNREFERENCED_PARAMETER(InitOnce);
    UNREFERENCED_PARAMETER(Parameter);
    UNREFERENCED_PARAMETER(Context);
    pEntries = (PLEECHRPC_HTTP_READ_CACHE_ENTRY)LocalAlloc(LMEM_ZEROINIT, sizeof(LEECHRPC_HTTP_READ_CACHE_ENTRY) * LEECHRPC_HTTP_READ_CACHE_ENTRIES);
    if(!pEntries) { return FALSE; }
    for(i = 0; i < LEECHRPC_HTTP_READ_CACHE_ENTRIES; i++) {
        pEntries[i].qwPageBase = MEM_SCATTER_ADDR_INVALID;
    }
    InitializeCriticalSection(&g_LeechRpcHttpReadCache.Lock);
    g_LeechRpcHttpReadCache.cEntries = LEECHRPC_HTTP_READ_CACHE_ENTRIES;
    g_LeechRpcHttpReadCache.pEntries = pEntries;
    g_LeechRpcHttpReadCache.fInitialized = TRUE;
    return TRUE;
}

static BOOL LeechRPC_HttpReadCacheEnsureInitialized()
{
    return InitOnceExecuteOnce(&g_LeechRpcHttpReadCacheInitOnce, LeechRPC_HttpReadCacheInit, NULL, NULL) ? TRUE : FALSE;
}

static VOID LeechRPC_HttpReadCacheReset()
{
    DWORD i;
    if(!LeechRPC_HttpReadCacheEnsureInitialized() || !g_LeechRpcHttpReadCache.fInitialized) { return; }
    EnterCriticalSection(&g_LeechRpcHttpReadCache.Lock);
    for(i = 0; i < g_LeechRpcHttpReadCache.cEntries; i++) {
        g_LeechRpcHttpReadCache.pEntries[i].qwPageBase = MEM_SCATTER_ADDR_INVALID;
        g_LeechRpcHttpReadCache.pEntries[i].dwTickMs = 0;
    }
    LeaveCriticalSection(&g_LeechRpcHttpReadCache.Lock);
}

static DWORD LeechRPC_HttpReadCacheHash(_In_ QWORD qwPageBase)
{
    QWORD x = (qwPageBase >> 12);
    x ^= (x >> 17);
    x ^= (x >> 31);
    return (DWORD)x;
}

static BOOL LeechRPC_HttpReadCacheRead(_In_ QWORD qwA, _In_ DWORD cb, _Out_writes_(cb) PBYTE pbOut)
{
    DWORD dwNow, dwMask, i;
    DWORD dwOffset;
    QWORD qwPageBase;
    if(!cb || (cb > LEECHRPC_HTTP_FETCH_PAGE_SIZE)) { return FALSE; }
    if(!LeechRPC_HttpReadCacheEnsureInitialized() || !g_LeechRpcHttpReadCache.fInitialized) { return FALSE; }
    qwPageBase = qwA & ~(QWORD)(LEECHRPC_HTTP_FETCH_PAGE_SIZE - 1);
    dwOffset = (DWORD)(qwA & (LEECHRPC_HTTP_FETCH_PAGE_SIZE - 1));
    if(dwOffset + cb > LEECHRPC_HTTP_FETCH_PAGE_SIZE) { return FALSE; }
    dwNow = GetTickCount();
    dwMask = g_LeechRpcHttpReadCache.cEntries - 1;
    EnterCriticalSection(&g_LeechRpcHttpReadCache.Lock);
    for(i = 0; i < 4; i++) {
        DWORD dwIndex = (LeechRPC_HttpReadCacheHash(qwPageBase) + i) & dwMask;
        PLEECHRPC_HTTP_READ_CACHE_ENTRY pEntry = &g_LeechRpcHttpReadCache.pEntries[dwIndex];
        if(pEntry->qwPageBase == qwPageBase) {
            if((DWORD)(dwNow - pEntry->dwTickMs) <= LEECHRPC_HTTP_READ_CACHE_TTL_MS) {
                memcpy(pbOut, pEntry->pbPage + dwOffset, cb);
                LeaveCriticalSection(&g_LeechRpcHttpReadCache.Lock);
                return TRUE;
            }
            break;
        }
        if(pEntry->qwPageBase == MEM_SCATTER_ADDR_INVALID) { break; }
    }
    LeaveCriticalSection(&g_LeechRpcHttpReadCache.Lock);
    return FALSE;
}

static VOID LeechRPC_HttpReadCacheStorePage(_In_ QWORD qwPageBase, _In_reads_(LEECHRPC_HTTP_FETCH_PAGE_SIZE) const BYTE *pbPage)
{
    DWORD dwNow, dwMask, i;
    DWORD dwVictimIdx = 0, dwVictimAge = 0;
    BOOL fVictimSet = FALSE;
    if(!LeechRPC_HttpReadCacheEnsureInitialized() || !g_LeechRpcHttpReadCache.fInitialized) { return; }
    qwPageBase &= ~(QWORD)(LEECHRPC_HTTP_FETCH_PAGE_SIZE - 1);
    dwNow = GetTickCount();
    dwMask = g_LeechRpcHttpReadCache.cEntries - 1;
    EnterCriticalSection(&g_LeechRpcHttpReadCache.Lock);
    for(i = 0; i < 4; i++) {
        DWORD dwIndex = (LeechRPC_HttpReadCacheHash(qwPageBase) + i) & dwMask;
        PLEECHRPC_HTTP_READ_CACHE_ENTRY pEntry = &g_LeechRpcHttpReadCache.pEntries[dwIndex];
        if((pEntry->qwPageBase == qwPageBase) || (pEntry->qwPageBase == MEM_SCATTER_ADDR_INVALID)) {
            dwVictimIdx = dwIndex;
            fVictimSet = TRUE;
            break;
        }
        if(!fVictimSet || ((DWORD)(dwNow - pEntry->dwTickMs) > dwVictimAge)) {
            dwVictimAge = (DWORD)(dwNow - pEntry->dwTickMs);
            dwVictimIdx = dwIndex;
            fVictimSet = TRUE;
        }
    }
    if(fVictimSet) {
        PLEECHRPC_HTTP_READ_CACHE_ENTRY pVictim = &g_LeechRpcHttpReadCache.pEntries[dwVictimIdx];
        pVictim->qwPageBase = qwPageBase;
        pVictim->dwTickMs = dwNow;
        memcpy(pVictim->pbPage, pbPage, LEECHRPC_HTTP_FETCH_PAGE_SIZE);
    }
    LeaveCriticalSection(&g_LeechRpcHttpReadCache.Lock);
}

static BOOL LeechRPC_HttpScatterGetSinglePage(_In_ PMEM_SCATTER pMEM, _Out_ PQWORD pqwPageBase)
{
    DWORD dwOffset;
    if(!pMEM || (pMEM->cb == 0) || (pMEM->cb > LEECHRPC_HTTP_FETCH_PAGE_SIZE)) { return FALSE; }
    dwOffset = (DWORD)(pMEM->qwA & (LEECHRPC_HTTP_FETCH_PAGE_SIZE - 1));
    if(dwOffset + pMEM->cb > LEECHRPC_HTTP_FETCH_PAGE_SIZE) { return FALSE; }
    *pqwPageBase = pMEM->qwA & ~(QWORD)(LEECHRPC_HTTP_FETCH_PAGE_SIZE - 1);
    return TRUE;
}

static BOOL LeechRPC_HttpFillMemFromCache(_Inout_ PMEM_SCATTER pMEM)
{
    if(!pMEM || pMEM->f || MEM_SCATTER_ADDR_ISINVALID(pMEM)) { return FALSE; }
    if(LeechRPC_HttpReadCacheRead(pMEM->qwA, pMEM->cb, pMEM->pb)) {
        pMEM->f = TRUE;
        return TRUE;
    }
    return FALSE;
}

static int __cdecl LeechRPC_QwordCmp(_In_ const void *pA, _In_ const void *pB)
{
    const QWORD qwA = *(const QWORD*)pA;
    const QWORD qwB = *(const QWORD*)pB;
    if(qwA < qwB) { return -1; }
    if(qwA > qwB) { return 1; }
    return 0;
}

static BOOL LeechRPC_PageListAppendUnique(_Inout_updates_(cListMax) PQWORD pqwList, _Inout_ PDWORD pcList, _In_ DWORD cListMax, _In_ QWORD qwPage)
{
    DWORD i;
    for(i = 0; i < *pcList; i++) {
        if(pqwList[i] == qwPage) { return TRUE; }
    }
    if(*pcList >= cListMax) { return FALSE; }
    pqwList[*pcList] = qwPage;
    (*pcList)++;
    return TRUE;
}

static VOID LeechRPC_ReadScatter_HttpFetchPages(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cPages, _In_reads_(cPages) PQWORD pqwPages)
{
    DWORD iPage = 0;
    while(iPage < cPages) {
        DWORD i;
        DWORD cChunk = min(cPages - iPage, (DWORD)LEECHRPC_HTTP_FETCH_MAX_PAGES_PER_REQ);
        PMEM_SCATTER pChunkMEMs = NULL;
        PPMEM_SCATTER ppChunkMEMs = NULL;
        PBYTE pbChunkData = NULL;
        cChunk = min(cChunk, (DWORD)LEECHRPC_SCATTER_MAX_MEMS_PER_REQ);
        pChunkMEMs = (PMEM_SCATTER)LocalAlloc(LMEM_ZEROINIT, sizeof(MEM_SCATTER) * cChunk);
        ppChunkMEMs = (PPMEM_SCATTER)LocalAlloc(LMEM_ZEROINIT, sizeof(PMEM_SCATTER) * cChunk);
        pbChunkData = (PBYTE)LocalAlloc(0, cChunk * LEECHRPC_HTTP_FETCH_PAGE_SIZE);
        if(!pChunkMEMs || !ppChunkMEMs || !pbChunkData) {
            LocalFree(pChunkMEMs);
            LocalFree(ppChunkMEMs);
            LocalFree(pbChunkData);
            return;
        }
        for(i = 0; i < cChunk; i++) {
            pChunkMEMs[i].version = MEM_SCATTER_VERSION;
            pChunkMEMs[i].f = FALSE;
            pChunkMEMs[i].qwA = pqwPages[iPage + i];
            pChunkMEMs[i].pb = pbChunkData + ((SIZE_T)i * LEECHRPC_HTTP_FETCH_PAGE_SIZE);
            pChunkMEMs[i].cb = LEECHRPC_HTTP_FETCH_PAGE_SIZE;
            pChunkMEMs[i].iStack = 0;
            ppChunkMEMs[i] = &pChunkMEMs[i];
        }
        LeechRPC_ReadScatter_Impl(ctxLC, cChunk, ppChunkMEMs);
        for(i = 0; i < cChunk; i++) {
            if(pChunkMEMs[i].f) {
                LeechRPC_HttpReadCacheStorePage(pChunkMEMs[i].qwA, pChunkMEMs[i].pb);
            }
        }
        LocalFree(pChunkMEMs);
        LocalFree(ppChunkMEMs);
        LocalFree(pbChunkData);
        iPage += cChunk;
    }
}

static VOID LeechRPC_ReadScatter_HttpOptimized(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    DWORD i;
    DWORD cMissMEMs = 0;
    DWORD cReqPages = 0;
    DWORD cReqPagesUnique = 0;
    DWORD cFetchPages = 0;
    DWORD cDirectMiss = 0;
    DWORD cFetchPagesMax = 0;
    DWORD cExtraBudget = 0;
    PMEM_SCATTER pMEM;
    PPMEM_SCATTER ppMissMEMs = NULL;
    PQWORD pqwReqPages = NULL;
    PQWORD pqwFetchPages = NULL;

    if(!cMEMs || !ppMEMs) { return; }

    for(i = 0; i < cMEMs; i++) {
        pMEM = ppMEMs[i];
        if(!pMEM || (pMEM->version != MEM_SCATTER_VERSION) || (pMEM->cb > 0x1000)) {
            LeechRPC_ReadScatter_ChunkedLegacy(ctxLC, cMEMs, ppMEMs);
            return;
        }
    }

    ppMissMEMs = (PPMEM_SCATTER)LocalAlloc(LMEM_ZEROINIT, sizeof(PMEM_SCATTER) * cMEMs);
    pqwReqPages = (PQWORD)LocalAlloc(0, sizeof(QWORD) * cMEMs);
    if(!ppMissMEMs || !pqwReqPages) {
        LocalFree(ppMissMEMs);
        LocalFree(pqwReqPages);
        LeechRPC_ReadScatter_Packed(ctxLC, cMEMs, ppMEMs);
        return;
    }

    for(i = 0; i < cMEMs; i++) {
        QWORD qwPageBase = 0;
        pMEM = ppMEMs[i];
        if(pMEM->f || MEM_SCATTER_ADDR_ISINVALID(pMEM)) { continue; }
        if(LeechRPC_HttpFillMemFromCache(pMEM)) { continue; }
        ppMissMEMs[cMissMEMs++] = pMEM;
        if(LeechRPC_HttpScatterGetSinglePage(pMEM, &qwPageBase)) {
            pqwReqPages[cReqPages++] = qwPageBase;
        }
    }

    if(cReqPages) {
        DWORD iRun;
        DWORD cExtraAdded = 0;
        qsort(pqwReqPages, cReqPages, sizeof(QWORD), LeechRPC_QwordCmp);
        cReqPagesUnique = 1;
        for(i = 1; i < cReqPages; i++) {
            if(pqwReqPages[i] != pqwReqPages[cReqPagesUnique - 1]) {
                pqwReqPages[cReqPagesUnique++] = pqwReqPages[i];
            }
        }
        cExtraBudget = (cReqPagesUnique * LEECHRPC_HTTP_PREFETCH_EXTRA_RATIO_PERCENT) / 100;
        cExtraBudget = min(cExtraBudget, (DWORD)LEECHRPC_HTTP_PREFETCH_EXTRA_PAGES_ABSOLUTE_MAX);
        cFetchPagesMax = cReqPagesUnique + cExtraBudget + LEECHRPC_HTTP_PREFETCH_AHEAD_PAGES + 8;
        pqwFetchPages = (PQWORD)LocalAlloc(0, sizeof(QWORD) * cFetchPagesMax);
        if(pqwFetchPages) {
            for(i = 0; i < cReqPagesUnique; i++) {
                LeechRPC_PageListAppendUnique(pqwFetchPages, &cFetchPages, cFetchPagesMax, pqwReqPages[i]);
            }
            for(iRun = 0; (iRun < cReqPagesUnique) && (cExtraAdded < cExtraBudget); ) {
                DWORD j;
                DWORD iRunEnd = iRun;
                QWORD qwRunTail;
                while((iRunEnd + 1 < cReqPagesUnique) && (pqwReqPages[iRunEnd + 1] == pqwReqPages[iRunEnd] + LEECHRPC_HTTP_FETCH_PAGE_SIZE)) {
                    iRunEnd++;
                }
                qwRunTail = pqwReqPages[iRunEnd];
                for(j = 1; (j <= LEECHRPC_HTTP_PREFETCH_AHEAD_PAGES) && (cExtraAdded < cExtraBudget); j++) {
                    if(!LeechRPC_PageListAppendUnique(pqwFetchPages, &cFetchPages, cFetchPagesMax, qwRunTail + ((QWORD)j * LEECHRPC_HTTP_FETCH_PAGE_SIZE))) {
                        break;
                    }
                    cExtraAdded++;
                }
                iRun = iRunEnd + 1;
            }
            if(cFetchPages > 1) {
                qsort(pqwFetchPages, cFetchPages, sizeof(QWORD), LeechRPC_QwordCmp);
            }
            LeechRPC_ReadScatter_HttpFetchPages(ctxLC, cFetchPages, pqwFetchPages);
        }
    }

    for(i = 0; i < cMissMEMs; i++) {
        pMEM = ppMissMEMs[i];
        if(!pMEM->f && LeechRPC_HttpFillMemFromCache(pMEM)) { continue; }
        ppMissMEMs[cDirectMiss++] = pMEM;
    }

    if(cDirectMiss) {
        LeechRPC_ReadScatter_Packed(ctxLC, cDirectMiss, ppMissMEMs);
        for(i = 0; i < cDirectMiss; i++) {
            QWORD qwPageBase = 0;
            pMEM = ppMissMEMs[i];
            if(!pMEM->f) { continue; }
            if((pMEM->cb == LEECHRPC_HTTP_FETCH_PAGE_SIZE) && LeechRPC_HttpScatterGetSinglePage(pMEM, &qwPageBase) && (pMEM->qwA == qwPageBase)) {
                LeechRPC_HttpReadCacheStorePage(qwPageBase, pMEM->pb);
            }
        }
    }

    LocalFree(ppMissMEMs);
    LocalFree(pqwReqPages);
    LocalFree(pqwFetchPages);
}

#else
static VOID LeechRPC_HttpReadCacheReset()
{
}
#endif

VOID LeechRPC_ReadScatter(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
#if LEECHRPC_HTTP_READ_OPT_ENABLE && defined(_WIN32)
    PLEECHRPC_CLIENT_CONTEXT ctx = (PLEECHRPC_CLIENT_CONTEXT)ctxLC->hDevice;
    if(ctx && ctx->fIsProtoHTTP) {
        LeechRPC_ReadScatter_HttpOptimized(ctxLC, cMEMs, ppMEMs);
        return;
    }
#endif
    LeechRPC_ReadScatter_Packed(ctxLC, cMEMs, ppMEMs);
}

VOID LeechRPC_WriteScatter_Impl(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    PBOOL pfRsp;
    DWORD i, cbReqData;
    PLEECHRPC_MSG_BIN pMsgReq = NULL;
    PLEECHRPC_MSG_BIN pMsgRsp = NULL;
    PMEM_SCATTER pMEM, pReqWrMEM;
    PBYTE pbReqWrData;
    // 1: prepare message to send
    cbReqData = cMEMs * (sizeof(MEM_SCATTER) + 0x1000);
    if(!(pMsgReq = LocalAlloc(0, sizeof(LEECHRPC_MSG_BIN) + cbReqData))) { goto fail; }
    ZeroMemory(pMsgReq, sizeof(LEECHRPC_MSG_BIN));
    pMsgReq->tpMsg = LEECHRPC_MSGTYPE_WRITESCATTER_REQ;
    pMsgReq->qwData[0] = cMEMs;
    pMsgReq->cb = cbReqData;
    pReqWrMEM = (PMEM_SCATTER)pMsgReq->pb;
    pbReqWrData = pMsgReq->pb + cMEMs * sizeof(MEM_SCATTER);
    for(i = 0; i < cMEMs; i++) {
        pMEM = ppMEMs[i];
        if(pMEM->cb > 0x1000) { goto fail; }
        memcpy(pReqWrMEM + i, pMEM, sizeof(MEM_SCATTER));
        memcpy(pbReqWrData, pMEM->pb, pMEM->cb);
        pbReqWrData += pMEM->cb;
    }
    // 2: transmit
    if(!LeechRPC_SubmitCommand(ctxLC, (PLEECHRPC_MSG_HDR)pMsgReq, LEECHRPC_MSGTYPE_WRITESCATTER_RSP, (PPLEECHRPC_MSG_HDR)&pMsgRsp)) { goto fail; }
    // 3: parse result (1 BOOL per cMEM)
    if(pMsgRsp->cb < cMEMs * sizeof(BOOL)) { goto fail; }
    pfRsp = (PBOOL)pMsgRsp->pb;
    for(i = 0; i < cMEMs; i++) {
        ppMEMs[i]->f = pfRsp[i] ? TRUE : FALSE;
    }
fail:
    LocalFree(pMsgReq);
    LocalFree(pMsgRsp);
}

VOID LeechRPC_WriteScatter(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    DWORD cMEMsChunk;
    while(cMEMs) {     // write max 32MB at a time.
        cMEMsChunk = min(cMEMs, (DWORD)LEECHRPC_SCATTER_MAX_MEMS_PER_REQ);
        LeechRPC_WriteScatter_Impl(ctxLC, cMEMsChunk, ppMEMs);
        ppMEMs += cMEMsChunk;
        cMEMs -= cMEMsChunk;
    }
}
_Success_(return)
BOOL LeechRPC_GetOption(_In_ PLC_CONTEXT ctxLC, _In_ QWORD fOption, _Out_ PQWORD pqwValue)
{
    BOOL result;
    LEECHRPC_MSG_DATA MsgReq = { 0 };
    PLEECHRPC_MSG_DATA pMsgRsp = NULL;
    Util_LogFileA("RIVERCLIENT_GETOPT: begin fopt=0x%016llx", fOption);
    // 1: prepare message to send
    MsgReq.tpMsg = LEECHRPC_MSGTYPE_GETOPTION_REQ;
    MsgReq.qwData[0] = fOption;
    // 2: transmit & get result
    result = LeechRPC_SubmitCommand(ctxLC, (PLEECHRPC_MSG_HDR)&MsgReq, LEECHRPC_MSGTYPE_GETOPTION_RSP, (PPLEECHRPC_MSG_HDR)&pMsgRsp);
    *pqwValue = result ? pMsgRsp->qwData[0] : 0;
    if(result) {
        Util_LogFileA("RIVERCLIENT_GETOPT: success fopt=0x%016llx value=0x%016llx", fOption, *pqwValue);
    } else {
        Util_LogFileA("RIVERCLIENT_GETOPT: fail fopt=0x%016llx", fOption);
    }
    LocalFree(pMsgRsp);
    return result;
}

_Success_(return)
BOOL LeechRPC_SetOption(_In_ PLC_CONTEXT ctxLC, _In_ QWORD fOption, _In_ QWORD qwValue)
{
    BOOL result;
    LEECHRPC_MSG_DATA MsgReq = { 0 };
    PLEECHRPC_MSG_HDR pMsgRsp = NULL;
    // 1: prepare message to send
    MsgReq.tpMsg = LEECHRPC_MSGTYPE_SETOPTION_REQ;
    MsgReq.qwData[0] = fOption;
    MsgReq.qwData[1] = qwValue;
    // 2: transmit & get result
    result = LeechRPC_SubmitCommand(ctxLC, (PLEECHRPC_MSG_HDR)&MsgReq, LEECHRPC_MSGTYPE_SETOPTION_RSP, (PPLEECHRPC_MSG_HDR)&pMsgRsp);
    LocalFree(pMsgRsp);
    return result;
}

//
// struct definitions from vmmdll to verify / fixup vfs related commands
//
#define __VFS_FILELISTBLOB_VERSION          0xf88f0001

typedef struct td__VFS_FILELISTBLOB_ENTRY {
    ULONG64 ouszName;                       // byte offset to string from VMMDLL_VFS_FILELISTBLOB.uszMultiText
    ULONG64 cbFileSize;                     // -1 == directory
    BYTE pbExInfoOpaque[32];
} __VFS_FILELISTBLOB_ENTRY, *P__VFS_FILELISTBLOB_ENTRY;

typedef struct td__VFS_FILELISTBLOB {
    DWORD dwVersion;                        // VMMDLL_VFS_FILELISTBLOB_VERSION
    DWORD cbStruct;
    DWORD cFileEntry;
    DWORD cbMultiText;
    union {
        LPSTR uszMultiText;
        QWORD _Reserved;
    };
    DWORD _FutureUse[8];
    __VFS_FILELISTBLOB_ENTRY FileEntry[0];
} __VFS_FILELISTBLOB, *P__VFS_FILELISTBLOB;

/*
* Verify incoming vfs (virtual file system) data from untrusted remote system
* for basic syntax. This to ensure the remote, potentially infected system,
* don't cause any security risks by callers trusting data.
* -- fCMD
* -- pMsgRsp
* -- return
*/
_Success_(return)
BOOL LeechRPC_Command_VerifyUntrustedVfsRsp(_In_ ULONG64 fCMD, _In_ PLEECHRPC_MSG_BIN pMsgRsp)
{
    PLC_CMD_AGENT_VFS_RSP pRsp;
    P__VFS_FILELISTBLOB pVfs;
    DWORD i;
    // 1: general
    if(pMsgRsp->cb < sizeof(LC_CMD_AGENT_VFS_RSP)) { return FALSE; }
    pRsp = (PLC_CMD_AGENT_VFS_RSP)pMsgRsp->pb;
    if(pRsp->dwVersion != LC_CMD_AGENT_VFS_RSP_VERSION) { return FALSE; }
    if(pMsgRsp->cb != sizeof(LC_CMD_AGENT_VFS_RSP) + pRsp->cb) { return FALSE; }
    // 2: specific
    if(fCMD == LC_CMD_AGENT_VFS_READ) {
        return (pRsp->cbReadWrite == pRsp->cb);
    }
    if(fCMD == LC_CMD_AGENT_VFS_WRITE) {
        return (0 == pRsp->cb);
    }
    if(fCMD == LC_CMD_AGENT_VFS_LIST) {
        if(pRsp->cb < sizeof(__VFS_FILELISTBLOB)) { return FALSE; }
        if(pRsp->pb[pRsp->cb - 1] != 0) { return FALSE; }
        pVfs = (P__VFS_FILELISTBLOB)pRsp->pb;
        if((pVfs->dwVersion != __VFS_FILELISTBLOB_VERSION) || (pRsp->cb != pVfs->cbStruct) || (pVfs->cbMultiText == 0)) { return FALSE; }
        if(pRsp->cb != sizeof(__VFS_FILELISTBLOB) + pVfs->cFileEntry * sizeof(__VFS_FILELISTBLOB_ENTRY) + pVfs->cbMultiText) { return FALSE; }
        if(pRsp->pb[sizeof(__VFS_FILELISTBLOB) + pVfs->cFileEntry * sizeof(__VFS_FILELISTBLOB_ENTRY)] != 0) { return FALSE; }
        pVfs->uszMultiText = (LPSTR)(sizeof(__VFS_FILELISTBLOB) + pVfs->cFileEntry * sizeof(__VFS_FILELISTBLOB_ENTRY));
        for(i = 0; i < pVfs->cFileEntry; i++) {
            if(pVfs->FileEntry[i].ouszName >= pVfs->cbMultiText) { return FALSE; }
        }
        return TRUE;
    }
    return FALSE;
}

_Success_(return)
BOOL LeechRPC_Command(
    _In_ PLC_CONTEXT ctxLC,
    _In_ ULONG64 fCMD,
    _In_ DWORD cbDataIn,
    _In_reads_opt_(cbDataIn) PBYTE pbDataIn,
    _Out_opt_ PBYTE *ppbDataOut,
    _Out_opt_ PDWORD pcbDataOut
) {
    BOOL result;
    PLEECHRPC_MSG_BIN pMsgReq = NULL;
    PLEECHRPC_MSG_BIN pMsgRsp = NULL;
    Util_LogFileA("RIVERCLIENT_CMD: begin fcmd=0x%016llx cb_in=%u", fCMD, cbDataIn);
    // 1: prepare message to send
    if(!pbDataIn && cbDataIn) { return FALSE; }
    if(fCMD & 0x2000000000000000) { return FALSE; }     // command is marked as no-remote.
    if(!(pMsgReq = LocalAlloc(0, sizeof(LEECHRPC_MSG_BIN) + cbDataIn))) { return FALSE; }
    ZeroMemory(pMsgReq, sizeof(LEECHRPC_MSG_BIN));
    pMsgReq->tpMsg = LEECHRPC_MSGTYPE_COMMAND_REQ;
    pMsgReq->cb = cbDataIn;
    pMsgReq->qwData[0] = fCMD;
    pMsgReq->qwData[1] = 0;
    if(pbDataIn) {
        memcpy(pMsgReq->pb, pbDataIn, cbDataIn);
    }
    // 2: transmit & get result
    result = LeechRPC_SubmitCommand(ctxLC, (PLEECHRPC_MSG_HDR)pMsgReq, LEECHRPC_MSGTYPE_COMMAND_RSP, (PPLEECHRPC_MSG_HDR)&pMsgRsp);
    if(result && ((fCMD == LC_CMD_AGENT_VFS_LIST) || (fCMD == LC_CMD_AGENT_VFS_READ) || (fCMD == LC_CMD_AGENT_VFS_WRITE))) {
        result = LeechRPC_Command_VerifyUntrustedVfsRsp(fCMD, pMsgRsp);
    }
    if(result) {
        if(pcbDataOut) { *pcbDataOut = pMsgRsp->cb; }
        if(ppbDataOut) {
            if((*ppbDataOut = LocalAlloc(0, pMsgRsp->cb))) {
                memcpy(*ppbDataOut, pMsgRsp->pb, pMsgRsp->cb);
            } else {
                result = FALSE;
            }
        }
    }
    if(result) {
        Util_LogFileA("RIVERCLIENT_CMD: success fcmd=0x%016llx cb_out=%u", fCMD, pMsgRsp ? pMsgRsp->cb : 0);
    } else {
        Util_LogFileA("RIVERCLIENT_CMD: fail fcmd=0x%016llx", fCMD);
    }
    if(!result && pcbDataOut) { *pcbDataOut = 0; }
    LocalFree(pMsgReq);
    LocalFree(pMsgRsp);
    return result;
}



//-----------------------------------------------------------------------------
// OPEN FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

_Success_(return)
BOOL LeechRpc_Open(_Inout_ PLC_CONTEXT ctxLC, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo)
{
    BOOL f;
    PLEECHRPC_CLIENT_CONTEXT ctx;
    CHAR _szBufferArg[MAX_PATH], _szBufferOpt[MAX_PATH];
    LEECHRPC_MSG_OPEN MsgReq = { 0 };
    PLEECHRPC_MSG_OPEN pMsgRsp = NULL;
    LPSTR szArg1, szArg2, szArg3;
    LPSTR aszOpt[8];
    DWORD i, dwPort = 0;
    int(*pfn_printf_opt_tmp)(_In_z_ _Printf_format_string_ char const* const _Format, ...);
    if(ppLcCreateErrorInfo) { *ppLcCreateErrorInfo = NULL; }
    Util_LogFileA("RIVERCLIENT_OPEN: begin remote=%s device=%s device_name=%s", ctxLC->Config.szRemote, ctxLC->Config.szDevice, ctxLC->Config.szDeviceName);
    ctx = (PLEECHRPC_CLIENT_CONTEXT)LocalAlloc(LMEM_ZEROINIT, sizeof(LEECHRPC_CLIENT_CONTEXT));
    if(!ctx) { return FALSE; }
    ctxLC->hDevice = (HANDLE)ctx;
    if(!_stricmp(ctxLC->Config.szDeviceName, "grpc")) { ctx->fIsProtoGRpc = TRUE; }
    if(!_stricmp(ctxLC->Config.szDeviceName, "rpc")) { ctx->fIsProtoRpc = TRUE; }
    if(!_stricmp(ctxLC->Config.szDeviceName, "smb")) { ctx->fIsProtoSmb = TRUE; }
    if(!_stricmp(ctxLC->Config.szDeviceName, "http")) { ctx->fIsProtoHTTP = TRUE; }
    if(!ctx->fIsProtoGRpc && !ctx->fIsProtoRpc && !ctx->fIsProtoSmb && !ctx->fIsProtoHTTP) {
        lcprintf(ctxLC, "REMOTE: ERROR: No valid remote transport protocol specified.\n");
        goto fail;
    }
    LeechRPC_ClientPerfEnsureInitialized();
    LeechRPC_ClientPerfReset();
    LeechRPC_HttpReadCacheReset();
    if(ctx->fIsProtoRpc || ctx->fIsProtoSmb) {
#if !LEECHRPC_ENABLE_NATIVE_RPC
        lcprintf(ctxLC, "REMOTE: ERROR: Native MS-RPC transport is disabled at compile time.\n");
        goto fail;
#else
        // RPC SPECIFIC INITIALIZATION BELOW:
        ctxLC->Rpc.fCompress = !ctxLC->Config.fRemoteDisableCompress;
        // parse arguments
        Util_Split3(ctxLC->Config.szRemote + 6, ':', _szBufferArg, &szArg1, &szArg2, &szArg3);
        if(!szArg1 || !szArg1[0] || !szArg2 || !szArg2[0]) { goto fail; }
        // Argument1 : Auth method, insecure | ntlm | kerberos_spn
        if(!_stricmp("insecure", szArg1)) {
            ctx->fIsAuthInsecure = TRUE;
        } else if(!_stricmp("ntlm", szArg1)) {
            ctx->fIsAuthNTLM = TRUE;
        } else {
            strncpy_s(ctx->szRemoteSPN, _countof(ctx->szRemoteSPN), szArg1, MAX_PATH);
            ctx->fIsAuthKerberos = TRUE;
        }
        // Argument2 : Tcp Address.
        strncpy_s(ctx->szTcpAddr, _countof(ctx->szTcpAddr), szArg2, MAX_PATH);
        // Argument3 : Options.
        if(szArg3[0]) {
            Util_SplitN(szArg3, ',', 5, _szBufferOpt, aszOpt);
            for(i = 0; i < 5; i++) {
                if(0 == _stricmp("nocompress", aszOpt[i])) {
                    ctxLC->Rpc.fCompress = FALSE;
                }
                if(0 == _strnicmp("port=", aszOpt[i], 5)) {
                    dwPort = atoi(aszOpt[i] + 5);
                }
                if(0 == _stricmp("logon", aszOpt[i])) {
                    ctx->fIsAuthNTLMCredPrompt = ctx->fIsAuthNTLM;
                }
                if(0 == _strnicmp("user=", aszOpt[i], 5)) {
                    ctx->szAuthNtlmUserInitOnly = aszOpt[i] + 5;
                }
                if(0 == _strnicmp("password=", aszOpt[i], 9)) {
                    ctx->szAuthNtlmPasswordInitOnly = aszOpt[i] + 9;
                }
            }
        }
        ctx->fIsAuthNTLMCredPrompt = ctx->fIsAuthNTLMCredPrompt || ctx->szAuthNtlmUserInitOnly || ctx->szAuthNtlmPasswordInitOnly;
        if(dwPort == 0) {
            dwPort = 28473; // default port
        }
        _itoa_s(dwPort, ctx->szTcpPort, 6, 10);
        // initialize rpc connection and ping
        f = LeechRPC_RpcInitialize(ctxLC, ctx);
        ctx->szAuthNtlmUserInitOnly = NULL;
        ctx->szAuthNtlmPasswordInitOnly = NULL;
        SecureZeroMemory(_szBufferOpt, sizeof(_szBufferOpt));
        if(!f) {
            lcprintf(ctxLC, "REMOTE: ERROR: Unable to connect to remote service '%s'\n", ctxLC->Config.szRemote);
            goto fail;
        }
        if(!LeechRPC_Ping(ctxLC)) {
            lcprintf(ctxLC, "REMOTE: ERROR: Unable to ping remote service '%s'\n", ctxLC->Config.szRemote);
            goto fail;
        }
#endif
    }
    if(ctx->fIsProtoGRpc) {
        // RPC SPECIFIC INITIALIZATION BELOW:
        ctxLC->Rpc.fCompress = !ctxLC->Config.fRemoteDisableCompress;
        // parse arguments
        Util_Split3(ctxLC->Config.szRemote + 7, ':', _szBufferArg, &szArg1, &szArg2, &szArg3);
        if(!szArg1 || !szArg2 || !szArg2[0]) { goto fail; }
        // Argument1 : Auth method, insecure
        if(!_stricmp("insecure", szArg1)) {
            ctx->fIsAuthInsecure = TRUE;
        } else if(szArg1[0]) {
            strncpy_s(ctx->grpc.szServerCertHostnameOverride, _countof(ctx->grpc.szServerCertHostnameOverride), szArg1, _TRUNCATE);
        }
        // Argument2 : Tcp Address.
        strncpy_s(ctx->szTcpAddr, _countof(ctx->szTcpAddr), szArg2, MAX_PATH);
        // Argument3 : Options.
        if(szArg3[0]) {
            Util_SplitN(szArg3, ',', 6, _szBufferOpt, aszOpt);
            for(i = 0; i < 6; i++) {
                if(0 == _stricmp("nocompress", aszOpt[i])) {
                    ctxLC->Rpc.fCompress = FALSE;
                }
                if(0 == _strnicmp("port=", aszOpt[i], 5)) {
                    dwPort = atoi(aszOpt[i] + 5);
                }
                if(0 == _strnicmp("client-cert-p12-password=", aszOpt[i], 25)) {
                    strncpy_s(ctx->grpc.szClientTlsP12Password, _countof(ctx->grpc.szClientTlsP12Password), aszOpt[i] + 25, _TRUNCATE);
                }
                if(0 == _strnicmp("client-cert-p12=", aszOpt[i], 16)) {
                    strncpy_s(ctx->grpc.szClientTlsP12Path, _countof(ctx->grpc.szClientTlsP12Path), aszOpt[i] + 16, _TRUNCATE);
                }
                if(0 == _strnicmp("server-cert=", aszOpt[i], 12)) {
                    strncpy_s(ctx->grpc.szServerCertCaPath, _countof(ctx->grpc.szServerCertCaPath), aszOpt[i] + 12, _TRUNCATE);
                }
                if(0 == _strnicmp("server-cert-host-override=", aszOpt[i], 26)) {
                    strncpy_s(ctx->grpc.szServerCertHostnameOverride, _countof(ctx->grpc.szServerCertHostnameOverride), aszOpt[i] + 26, _TRUNCATE);
                }
            }
        }
        if(dwPort == 0) {
            dwPort = 28474; // default port
        }
        _itoa_s(dwPort, ctx->szTcpPort, 6, 10);
        // initialize rpc connection and ping
        f = LeechRPC_GRpcInitialize(ctxLC, ctx);
        SecureZeroMemory(_szBufferOpt, sizeof(_szBufferOpt));
        if(!f) {
            lcprintf(ctxLC, "REMOTE: ERROR: Unable to connect to remote gRPC service '%s'\n", ctxLC->Config.szRemote);
            goto fail;
        }
        if(!LeechRPC_Ping(ctxLC)) {
            lcprintf(ctxLC, "REMOTE: ERROR: Unable to ping remote gRPC service '%s'\n", ctxLC->Config.szRemote);
            goto fail;
        }
    }
    if(ctx->fIsProtoHTTP) {
        CHAR *pRemote = ctxLC->Config.szRemote + 7; // skip "http://"
        CHAR *pColon = strchr(pRemote, ':');
        CHAR *pComma = NULL;
        CHAR szHost[MAX_PATH] = { 0 };
        CHAR szPortStr[16] = { 0 };
        DWORD dwPort = LeechRPC_HttpGetDefaultBootstrapPort();
        DWORD cPoolRequested = LEECHRPC_HTTP_POOL_SIZE_DEFAULT;
        DWORD cPoolPrewarmed = 0;
        ctxLC->Rpc.fCompress = FALSE;
        ctxLC->Config.fRemoteDisableCompress = TRUE;
        if(pColon) {
            SIZE_T cchHost = min((SIZE_T)(pColon - pRemote), sizeof(szHost) - 1);
            memcpy(szHost, pRemote, cchHost);
            pComma = strchr(pColon + 1, ',');
            if(pComma) {
                SIZE_T cchPort = min((SIZE_T)(pComma - (pColon + 1)), sizeof(szPortStr) - 1);
                memcpy(szPortStr, pColon + 1, cchPort);
            } else {
                strncpy_s(szPortStr, _countof(szPortStr), pColon + 1, _TRUNCATE);
            }
        } else {
            strncpy_s(szHost, _countof(szHost), pRemote, _TRUNCATE);
        }
        if(!szHost[0]) { lcprintf(ctxLC, "REMOTE: ERROR: Invalid http host.\n"); goto fail; }
        strncpy_s(ctx->szHttpHost, _countof(ctx->szHttpHost), szHost, _TRUNCATE);
        if(szPortStr[0]) { dwPort = atoi(szPortStr); }
        if(dwPort == 0) { dwPort = LeechRPC_HttpGetDefaultBootstrapPort(); }
        _itoa_s(dwPort, ctx->szHttpPort, _countof(ctx->szHttpPort), 10);
        if(pComma && *(pComma + 1)) {
            Util_SplitN(pComma + 1, ',', 8, _szBufferOpt, aszOpt);
            for(i = 0; i < 8; i++) {
                if(0 == _strnicmp("pool=", aszOpt[i], 5)) {
                    cPoolRequested = (DWORD)atoi(aszOpt[i] + 5);
                }
            }
        }
#ifdef _WIN32
        {
            PLEECHRPC_HTTP_READMUX pMux = NULL;
            ctx->cHttpPoolActive = LeechRPC_HttpPoolNormalizeSize(cPoolRequested);
            InitializeCriticalSection(&ctx->HttpBootstrapLock);
            ctx->fHttpBootstrapLockInitialized = TRUE;
            if(!LeechRPC_HttpReadMuxEnsureInitializedStorage(ctx, &ctx->hHttpControlMux, &pMux)) {
                f = FALSE;
            } else {
                EnterCriticalSection(&pMux->Conn.Lock);
                f = LeechRPC_HttpReadMuxConnect_NoLock(ctx, pMux);
                LeaveCriticalSection(&pMux->Conn.Lock);
                cPoolPrewarmed = f ? 1 : 0;
            }
            if(!f) {
                lcprintf(
                    ctxLC,
                    "REMOTE: ERROR: Unable to initialize TCP transport '%s' (host=%s port=%s gai=%d wsa=%u)\n",
                    ctxLC->Config.szRemote,
                    ctx->szHttpHost,
                    ctx->szHttpPort,
                    ctx->iHttpLastGaiError,
                    ctx->dwHttpLastWsaError
                );
                lcprintf(ctxLC, "REMOTE: HINT: Verify remote RiverServer is listening on tcp/%s and firewall allows inbound.\n", ctx->szHttpPort);
                goto fail;
            }
        }
#endif /* _WIN32 */
        if(!LeechRPC_Ping(ctxLC)) {
            lcprintf(ctxLC, "REMOTE: WARNING: Unable to ping remote TCP transport '%s' - continue with open.\n", ctxLC->Config.szRemote);
        }
    }
    if(0 == _strnicmp(ctxLC->Config.szDevice, "existingremote", 14)) {
        for(i = 14; i < _countof(ctxLC->Config.szDevice); i++) {
            ctxLC->Config.szDevice[i - 6] = ctxLC->Config.szDevice[i];
            if(0 == ctxLC->Config.szDevice[i]) { break; }
        }
    }
    // try enable compression (if required)
    if(!ctx->fIsProtoHTTP) {
        ctxLC->Rpc.fCompress = ctxLC->Rpc.fCompress && LeechRPC_CompressInitialize(&ctx->Compress);
    } else {
        ctxLC->Rpc.fCompress = FALSE;
        ctxLC->Config.fRemoteDisableCompress = TRUE;
    }
    if(ctx->fIsProtoHTTP) {
        ctxLC->Config.fRemoteDisableCompress = TRUE;
    } else {
        ctxLC->Config.fRemoteDisableCompress = ctxLC->Config.fRemoteDisableCompress && !ctxLC->Rpc.fCompress;
    }
    // call open on the remote service
    Util_GenRandom((PBYTE)&ctxLC->Rpc.dwRpcClientId, sizeof(DWORD));
    MsgReq.tpMsg = LEECHRPC_MSGTYPE_OPEN_REQ;
    memcpy(&MsgReq.cfg, &ctxLC->Config, sizeof(LC_CONFIG));
    ZeroMemory(MsgReq.cfg.szRemote, _countof(MsgReq.cfg.szRemote));
    MsgReq.cfg.pfn_printf_opt = 0;
    if(!LeechRPC_SubmitCommand(ctxLC, (PLEECHRPC_MSG_HDR)&MsgReq, LEECHRPC_MSGTYPE_OPEN_RSP, (PPLEECHRPC_MSG_HDR)&pMsgRsp)) {
        Util_LogFileA("RIVERCLIENT_OPEN: remote open submit failed device=%s", ctxLC->Config.szDevice);
        lcprintf(ctxLC, "REMOTE: ERROR: Unable to open remote device #1 '%s'\n", ctxLC->Config.szDevice);
        goto fail;
    }
    if(!pMsgRsp->fValidOpen) {
        Util_LogFileA("RIVERCLIENT_OPEN: remote open rejected device=%s error_cb=%u", ctxLC->Config.szDevice, pMsgRsp->errorinfo.cbStruct);
        if((pMsgRsp->errorinfo.dwVersion == LC_CONFIG_ERRORINFO_VERSION) && (pMsgRsp->errorinfo.cbStruct < pMsgRsp->cbMsg) && ((pMsgRsp->errorinfo.cwszUserText * 2ULL) + sizeof(LC_CONFIG_ERRORINFO) < pMsgRsp->errorinfo.cbStruct)) {
            if((*ppLcCreateErrorInfo = LocalAlloc(LMEM_ZEROINIT, pMsgRsp->errorinfo.cbStruct))) {
                pMsgRsp->errorinfo.wszUserText[pMsgRsp->errorinfo.cwszUserText] = 0;
                memcpy(*ppLcCreateErrorInfo, &pMsgRsp->errorinfo, pMsgRsp->errorinfo.cbStruct);
            }
        }
        lcprintf(ctxLC, "REMOTE: ERROR: Unable to open remote device #2 '%s'\n", ctxLC->Config.szDevice);
        goto fail;
    }
    // sanity check positive result from remote service
    if(pMsgRsp->cfg.dwVersion != LC_CONFIG_VERSION) {
        Util_LogFileA("RIVERCLIENT_OPEN: invalid open response version=%u expected=%u", pMsgRsp->cfg.dwVersion, LC_CONFIG_VERSION);
        lcprintf(ctxLC, "REMOTE: ERROR: Invalid message received from remote service.\n");
        goto fail;
    }
    if(ctxLC->Rpc.fCompress && pMsgRsp->cfg.fRemoteDisableCompress) {
        ctxLC->Config.fRemoteDisableCompress = TRUE;
        ctxLC->Rpc.fCompress = FALSE;
        lcprintfv(ctxLC, "REMOTE: INFO: Compression disabled.\n");
    }
    // all ok - initialize this rpc device stub.
    ctx->hHousekeeperThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LeechRPC_KeepaliveThreadClient, ctxLC, 0, NULL);
    strncpy_s(pMsgRsp->cfg.szRemote, sizeof(pMsgRsp->cfg.szRemote), ctxLC->Config.szRemote, _TRUNCATE); // ctx from remote doesn't contain remote info ...
    pfn_printf_opt_tmp = ctxLC->Config.pfn_printf_opt;
    memcpy(&ctxLC->Config, &pMsgRsp->cfg, sizeof(LC_CONFIG));
    ctxLC->Config.pfn_printf_opt = pfn_printf_opt_tmp;
    ctxLC->Config.fRemote = TRUE;
    ctxLC->fMultiThread = TRUE;
    ctxLC->pfnClose = LeechRPC_Close;
    ctxLC->pfnReadScatter = LeechRPC_ReadScatter;
    ctxLC->pfnWriteScatter = LeechRPC_WriteScatter;
    ctxLC->pfnGetOption = LeechRPC_GetOption;
    ctxLC->pfnSetOption = LeechRPC_SetOption;
    ctxLC->pfnCommand = LeechRPC_Command;
    Util_LogFileA("RIVERCLIENT_OPEN: success device=%s remote=%s", ctxLC->Config.szDeviceName, ctxLC->Config.szRemote);
    lcprintfv(ctxLC, "REMOTE: Successfully opened remote device: %s\n", ctxLC->Config.szDeviceName);
    LocalFree(pMsgRsp);
    return TRUE;
fail:
    Util_LogFileA("RIVERCLIENT_OPEN: fail remote=%s device=%s", ctxLC->Config.szRemote, ctxLC->Config.szDevice);
    LeechRPC_Close(ctxLC);
    LocalFree(pMsgRsp);
    return FALSE;
}












