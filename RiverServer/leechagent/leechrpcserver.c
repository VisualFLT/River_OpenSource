// leechrpc.c : implementation of RPC server-side functionality.
//
// (c) Ulf Frisk, 2018-2026
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "leechagent.h"
#include "river_activation.h"
#include "leechagent_proc.h"
#include "leechrpc.h"
#include "leechrpc_h.h"
#include "util.h"
#include <stdio.h>
#include <stdarg.h>

#ifndef LEECHRPC_SERVER_LOCAL_LOG_ENABLE
#define LEECHRPC_SERVER_LOCAL_LOG_ENABLE 0
#endif

static VOID LeechRpc_ServerLocalLog(_In_z_ _Printf_format_string_ char const* const _Format, ...)
{
#if LEECHRPC_SERVER_LOCAL_LOG_ENABLE
    va_list argptr;
    va_start(argptr, _Format);
    vprintf(_Format, argptr);
    va_end(argptr);
#else
    UNREFERENCED_PARAMETER(_Format);
#endif
}

#ifndef LEECHRPC_SERVER_PERF_STATS_ENABLE
#define LEECHRPC_SERVER_PERF_STATS_ENABLE        1
#endif

#ifndef LEECHRPC_SERVER_PERF_LOG_INTERVAL_MS
#define LEECHRPC_SERVER_PERF_LOG_INTERVAL_MS     5000
#endif

typedef struct tdLEECHRPC_SERVER_PERF {
    BOOL fStarted;
    QWORD qwStartTickCount64;
    QWORD qwLastLogTickCount64;
    QWORD cOpen;
    QWORD cClose;
    QWORD cReqTotal;
    QWORD cReqFail;
    QWORD cReqPing;
    QWORD cReqKeepAlive;
    QWORD cReqOpen;
    QWORD cReqClose;
    QWORD cReqReadScatter;
    QWORD cReqWriteScatter;
    QWORD cReqGetOption;
    QWORD cReqSetOption;
    QWORD cReqCommand;
    QWORD cbInTotal;
    QWORD cbOutTotal;
    QWORD cReadScatterMemTotal;
    QWORD cbReadReqTotal;
    QWORD cbReadRspTotal;
    DWORD cActiveClientsLast;
    QWORD cActiveRequestsLast;
    QWORD qwOldestConnAgeMsLast;
    QWORD qwElapsedMsLast;
    QWORD cReqPerSecLast;
    QWORD cbInPerSecLast;
    QWORD cbOutPerSecLast;
} LEECHRPC_SERVER_PERF, *PLEECHRPC_SERVER_PERF;

typedef struct tdLEECHRPC_SERVER_CONTEXT {
    BOOL fValid;
    LEECHRPC_COMPRESS Compress;
    BOOL fInactivityWatcherThread;
    BOOL fInactivityWatcherThreadIsRunning;
    CRITICAL_SECTION LockClientList;
    struct {
        HANDLE hLC;
        HANDLE hPP;             // parent/child process context (used for child-process vfs operations)
        DWORD dwRpcClientID;
        DWORD cActiveRequests;
        QWORD qwLastTickCount64;
        QWORD qwConnectTickCount64;
    } ClientList[LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS];
    LEECHRPC_SERVER_PERF Perf;
} LEECHRPC_SERVER_CONTEXT, *PLEECHRPC_SERVER_CONTEXT;

LEECHRPC_SERVER_CONTEXT ctxLeechRpc = { 0 };

#define LEECHRPC_RESPPOOL_MAGIC 0x52504f4c
#define LEECHRPC_RESPPOOL_BUCKETS 6
#define LEECHRPC_RESPPOOL_LAYOUT_NORMAL 0
#define LEECHRPC_RESPPOOL_LAYOUT_FRAMEREADY 1
#define LEECHRPC_RESPPOOL_LAYOUT_MAX 2

typedef struct tdLEECHRPC_RESPONSE_POOL_HDR {
    DWORD dwMagic;
    DWORD iBucket;
    DWORD dwLayout;
    DWORD cbCapacity;
    DWORD cbPrefix;
    DWORD cbSuffix;
    struct tdLEECHRPC_RESPONSE_POOL_HDR *Flink;
} LEECHRPC_RESPONSE_POOL_HDR, *PLEECHRPC_RESPONSE_POOL_HDR;

static const DWORD g_cbLeechRpcResponsePoolBuckets[LEECHRPC_RESPPOOL_BUCKETS] = {
    0x00010000, 0x00040000, 0x00100000, 0x00400000, 0x01000000, 0x02000000
};
static const DWORD g_cLeechRpcResponsePoolBucketMax[LEECHRPC_RESPPOOL_BUCKETS] = {
    32, 24, 12, 6, 4, 2
};
static CRITICAL_SECTION g_LeechRpcResponsePoolLock;
static BOOL g_fLeechRpcResponsePoolInit = FALSE;
static PLEECHRPC_RESPONSE_POOL_HDR g_LeechRpcResponsePoolHead[LEECHRPC_RESPPOOL_LAYOUT_MAX][LEECHRPC_RESPPOOL_BUCKETS] = { 0 };
static DWORD g_cLeechRpcResponsePoolCount[LEECHRPC_RESPPOOL_LAYOUT_MAX][LEECHRPC_RESPPOOL_BUCKETS] = { 0 };

static DWORD LeechRpc_ResponsePoolBucketIndex(_In_ DWORD cb)
{
    DWORD i;
    for(i = 0; i < LEECHRPC_RESPPOOL_BUCKETS; i++) {
        if(cb <= g_cbLeechRpcResponsePoolBuckets[i]) {
            return i;
        }
    }
    return (DWORD)-1;
}

static PLEECHRPC_RESPONSE_POOL_HDR LeechRpc_ServerResponseHeaderFromPointer(_In_ PBYTE pb)
{
    return *(PLEECHRPC_RESPONSE_POOL_HDR*)(pb - sizeof(PVOID));
}

static PBYTE LeechRpc_ServerResponseAllocEx(_In_ DWORD cb, _In_ DWORD cbPrefixExtra, _In_ DWORD cbSuffix)
{
    DWORD dwLayout = cbPrefixExtra ? LEECHRPC_RESPPOOL_LAYOUT_FRAMEREADY : LEECHRPC_RESPPOOL_LAYOUT_NORMAL;
    DWORD cbPrefix = sizeof(PVOID) + cbPrefixExtra;
    DWORD iBucket = LeechRpc_ResponsePoolBucketIndex(cb + cbPrefixExtra + cbSuffix);
    PLEECHRPC_RESPONSE_POOL_HDR pHdr = NULL;
    PBYTE pbUser;
    if(g_fLeechRpcResponsePoolInit && (iBucket != (DWORD)-1)) {
        EnterCriticalSection(&g_LeechRpcResponsePoolLock);
        pHdr = g_LeechRpcResponsePoolHead[dwLayout][iBucket];
        if(pHdr) {
            g_LeechRpcResponsePoolHead[dwLayout][iBucket] = pHdr->Flink;
            g_cLeechRpcResponsePoolCount[dwLayout][iBucket]--;
            pHdr->Flink = NULL;
        }
        LeaveCriticalSection(&g_LeechRpcResponsePoolLock);
    }
    if(!pHdr) {
        DWORD cbCapacity = (iBucket != (DWORD)-1) ? g_cbLeechRpcResponsePoolBuckets[iBucket] : (cb + cbPrefixExtra + cbSuffix);
        pHdr = (PLEECHRPC_RESPONSE_POOL_HDR)LocalAlloc(LMEM_FIXED, sizeof(LEECHRPC_RESPONSE_POOL_HDR) + sizeof(PVOID) + cbPrefixExtra + cbCapacity + cbSuffix);
        if(!pHdr) {
            return NULL;
        }
        pHdr->dwMagic = LEECHRPC_RESPPOOL_MAGIC;
        pHdr->iBucket = iBucket;
        pHdr->dwLayout = dwLayout;
        pHdr->cbCapacity = cbCapacity;
        pHdr->cbPrefix = cbPrefix;
        pHdr->cbSuffix = cbSuffix;
        pHdr->Flink = NULL;
    }
    pbUser = (PBYTE)(pHdr + 1) + cbPrefix;
    *(PLEECHRPC_RESPONSE_POOL_HDR*)(pbUser - sizeof(PVOID)) = pHdr;
    return pbUser;
}

PBYTE LeechRpc_ServerResponseAlloc(_In_ DWORD cb)
{
    return LeechRpc_ServerResponseAllocEx(cb, 0, 0);
}

PBYTE LeechRpc_ServerResponseAllocFrameReady(_In_ DWORD cb)
{
    return LeechRpc_ServerResponseAllocEx(cb, sizeof(LEECHRPC_SECURE_FRAME_HDR), LEECHRPC_SECURE_TAG_SIZE);
}

BOOL LeechRpc_ServerResponseGetFrameBuffer(_In_ PBYTE pb, _In_ DWORD cbPlain, _Out_ PBYTE *ppbFrame, _Out_ DWORD *pcbFrame)
{
    PLEECHRPC_RESPONSE_POOL_HDR pHdr;
    if(!pb || !ppbFrame || !pcbFrame) { return FALSE; }
    pHdr = LeechRpc_ServerResponseHeaderFromPointer(pb);
    if(!pHdr || (pHdr->dwMagic != LEECHRPC_RESPPOOL_MAGIC) || (pHdr->dwLayout != LEECHRPC_RESPPOOL_LAYOUT_FRAMEREADY)) { return FALSE; }
    if((pHdr->cbPrefix < (sizeof(PVOID) + sizeof(LEECHRPC_SECURE_FRAME_HDR))) || (pHdr->cbSuffix < LEECHRPC_SECURE_TAG_SIZE)) {
        return FALSE;
    }
    *ppbFrame = pb - sizeof(LEECHRPC_SECURE_FRAME_HDR);
    *pcbFrame = sizeof(LEECHRPC_SECURE_FRAME_HDR) + cbPlain + LEECHRPC_SECURE_TAG_SIZE;
    return TRUE;
}

VOID LeechRpc_ServerResponseFree(_Pre_maybenull_ PBYTE pb)
{
    PLEECHRPC_RESPONSE_POOL_HDR pHdr;
    if(!pb) { return; }
    pHdr = LeechRpc_ServerResponseHeaderFromPointer(pb);
    if((pHdr->dwMagic != LEECHRPC_RESPPOOL_MAGIC) || (pHdr->iBucket >= LEECHRPC_RESPPOOL_BUCKETS) || (pHdr->dwLayout >= LEECHRPC_RESPPOOL_LAYOUT_MAX) || !g_fLeechRpcResponsePoolInit) {
        LocalFree(pHdr);
        return;
    }
    EnterCriticalSection(&g_LeechRpcResponsePoolLock);
    if(g_cLeechRpcResponsePoolCount[pHdr->dwLayout][pHdr->iBucket] >= g_cLeechRpcResponsePoolBucketMax[pHdr->iBucket]) {
        LeaveCriticalSection(&g_LeechRpcResponsePoolLock);
        LocalFree(pHdr);
        return;
    }
    pHdr->Flink = g_LeechRpcResponsePoolHead[pHdr->dwLayout][pHdr->iBucket];
    g_LeechRpcResponsePoolHead[pHdr->dwLayout][pHdr->iBucket] = pHdr;
    g_cLeechRpcResponsePoolCount[pHdr->dwLayout][pHdr->iBucket]++;
    LeaveCriticalSection(&g_LeechRpcResponsePoolLock);
}

#if LEECHRPC_SERVER_PERF_STATS_ENABLE
static VOID LeechRpc_PerfOnReadScatter(_In_ DWORD cMEMs, _In_ DWORD cbReq, _In_ DWORD cbRsp, _In_ BOOL fSuccess)
{
    EnterCriticalSection(&ctxLeechRpc.LockClientList);
    if(ctxLeechRpc.Perf.fStarted && fSuccess) {
        ctxLeechRpc.Perf.cReadScatterMemTotal += cMEMs;
        ctxLeechRpc.Perf.cbReadReqTotal += cbReq;
        ctxLeechRpc.Perf.cbReadRspTotal += cbRsp;
    }
    LeaveCriticalSection(&ctxLeechRpc.LockClientList);
}

static VOID LeechRpc_PerfOnRequest(_In_ LEECHRPC_MSGTYPE tpMsg, _In_ DWORD cbIn, _In_ DWORD cbOut, _In_ BOOL fSuccess)
{
    EnterCriticalSection(&ctxLeechRpc.LockClientList);
    if(ctxLeechRpc.Perf.fStarted) {
        if(tpMsg == LEECHRPC_MSGTYPE_PERF_REQ) {
            LeaveCriticalSection(&ctxLeechRpc.LockClientList);
            return;
        }
        ctxLeechRpc.Perf.cReqTotal++;
        ctxLeechRpc.Perf.cbInTotal += cbIn;
        ctxLeechRpc.Perf.cbOutTotal += cbOut;
        if(!fSuccess) {
            ctxLeechRpc.Perf.cReqFail++;
        }
        switch(tpMsg) {
            case LEECHRPC_MSGTYPE_PING_REQ:
                ctxLeechRpc.Perf.cReqPing++;
                break;
            case LEECHRPC_MSGTYPE_KEEPALIVE_REQ:
                ctxLeechRpc.Perf.cReqKeepAlive++;
                break;
            case LEECHRPC_MSGTYPE_OPEN_REQ:
                ctxLeechRpc.Perf.cReqOpen++;
                break;
            case LEECHRPC_MSGTYPE_CLOSE_REQ:
                ctxLeechRpc.Perf.cReqClose++;
                break;
            case LEECHRPC_MSGTYPE_READSCATTER_REQ:
                ctxLeechRpc.Perf.cReqReadScatter++;
                break;
            case LEECHRPC_MSGTYPE_WRITESCATTER_REQ:
                ctxLeechRpc.Perf.cReqWriteScatter++;
                break;
            case LEECHRPC_MSGTYPE_GETOPTION_REQ:
                ctxLeechRpc.Perf.cReqGetOption++;
                break;
            case LEECHRPC_MSGTYPE_SETOPTION_REQ:
                ctxLeechRpc.Perf.cReqSetOption++;
                break;
            case LEECHRPC_MSGTYPE_COMMAND_REQ:
                ctxLeechRpc.Perf.cReqCommand++;
                break;
            default:
                break;
        }
    }
    LeaveCriticalSection(&ctxLeechRpc.LockClientList);
}

static VOID LeechRpc_PerfLogSnapshot(_In_ BOOL fForce)
{
    DWORD i, cActiveClients = 0;
    QWORD cActiveRequests = 0, qwOldestConnAgeMs = 0;
    QWORD qwNow, qwElapsedMs, cReqPerSec, cbInPerSec, cbOutPerSec;
    LEECHRPC_SERVER_PERF Perf;
    EnterCriticalSection(&ctxLeechRpc.LockClientList);
    if(!ctxLeechRpc.Perf.fStarted) {
        LeaveCriticalSection(&ctxLeechRpc.LockClientList);
        return;
    }
    qwNow = GetTickCount64();
    if(!fForce && ctxLeechRpc.Perf.qwLastLogTickCount64 && (qwNow - ctxLeechRpc.Perf.qwLastLogTickCount64 < LEECHRPC_SERVER_PERF_LOG_INTERVAL_MS)) {
        LeaveCriticalSection(&ctxLeechRpc.LockClientList);
        return;
    }
    ctxLeechRpc.Perf.qwLastLogTickCount64 = qwNow;
    Perf = ctxLeechRpc.Perf;
    for(i = 0; i < LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS; i++) {
        if(ctxLeechRpc.ClientList[i].dwRpcClientID) {
            QWORD qwAge = 0;
            cActiveClients++;
            cActiveRequests += ctxLeechRpc.ClientList[i].cActiveRequests;
            if(ctxLeechRpc.ClientList[i].qwConnectTickCount64 && (qwNow > ctxLeechRpc.ClientList[i].qwConnectTickCount64)) {
                qwAge = qwNow - ctxLeechRpc.ClientList[i].qwConnectTickCount64;
                if(qwAge > qwOldestConnAgeMs) {
                    qwOldestConnAgeMs = qwAge;
                }
            }
        }
    }
    LeaveCriticalSection(&ctxLeechRpc.LockClientList);
    qwElapsedMs = (qwNow > Perf.qwStartTickCount64) ? (qwNow - Perf.qwStartTickCount64) : 1;
    if(!qwElapsedMs) { qwElapsedMs = 1; }
    cReqPerSec = (Perf.cReqTotal * 1000ULL) / qwElapsedMs;
    cbInPerSec = (Perf.cbInTotal * 1000ULL) / qwElapsedMs;
    cbOutPerSec = (Perf.cbOutTotal * 1000ULL) / qwElapsedMs;
    EnterCriticalSection(&ctxLeechRpc.LockClientList);
    if(ctxLeechRpc.Perf.fStarted) {
        ctxLeechRpc.Perf.cActiveClientsLast = cActiveClients;
        ctxLeechRpc.Perf.cActiveRequestsLast = cActiveRequests;
        ctxLeechRpc.Perf.qwOldestConnAgeMsLast = qwOldestConnAgeMs;
        ctxLeechRpc.Perf.qwElapsedMsLast = qwElapsedMs;
        ctxLeechRpc.Perf.cReqPerSecLast = cReqPerSec;
        ctxLeechRpc.Perf.cbInPerSecLast = cbInPerSec;
        ctxLeechRpc.Perf.cbOutPerSecLast = cbOutPerSec;
    }
    LeaveCriticalSection(&ctxLeechRpc.LockClientList);
}
#else
static VOID LeechRpc_PerfOnReadScatter(_In_ DWORD cMEMs, _In_ DWORD cbReq, _In_ DWORD cbRsp, _In_ BOOL fSuccess)
{
    UNREFERENCED_PARAMETER(cMEMs);
    UNREFERENCED_PARAMETER(cbReq);
    UNREFERENCED_PARAMETER(cbRsp);
    UNREFERENCED_PARAMETER(fSuccess);
}

static VOID LeechRpc_PerfOnRequest(_In_ LEECHRPC_MSGTYPE tpMsg, _In_ DWORD cbIn, _In_ DWORD cbOut, _In_ BOOL fSuccess)
{
    UNREFERENCED_PARAMETER(tpMsg);
    UNREFERENCED_PARAMETER(cbIn);
    UNREFERENCED_PARAMETER(cbOut);
    UNREFERENCED_PARAMETER(fSuccess);
}

static VOID LeechRpc_PerfLogSnapshot(_In_ BOOL fForce)
{
    UNREFERENCED_PARAMETER(fForce);
}
#endif

#ifdef _WIN32
typedef struct tdLEECHRPC_READSCATTER_TLS {
    PPMEM_SCATTER ppMEMs;
    DWORD cbMEMs;
    PBYTE pbData;
    DWORD cbData;
} LEECHRPC_READSCATTER_TLS, *PLEECHRPC_READSCATTER_TLS;

static INIT_ONCE g_LeechRpcReadScatterTlsInitOnce = INIT_ONCE_STATIC_INIT;
static DWORD g_dwLeechRpcReadScatterTlsIndex = TLS_OUT_OF_INDEXES;

static BOOL CALLBACK LeechRPC_ReadScatterTlsInit(_In_ PINIT_ONCE InitOnce, _In_opt_ PVOID Parameter, _Out_opt_ PVOID *Context)
{
    UNREFERENCED_PARAMETER(InitOnce);
    UNREFERENCED_PARAMETER(Parameter);
    UNREFERENCED_PARAMETER(Context);
    g_dwLeechRpcReadScatterTlsIndex = TlsAlloc();
    return g_dwLeechRpcReadScatterTlsIndex != TLS_OUT_OF_INDEXES;
}

_Success_(return)
static BOOL LeechRPC_ReadScatterEnsureTlsBuffers(_In_ DWORD cMEMs, _In_ DWORD cbMax, _Out_ PPMEM_SCATTER *pppMEMs, _Out_ PBYTE *ppbData)
{
    DWORD cbMEMs = cMEMs * sizeof(PMEM_SCATTER);
    PLEECHRPC_READSCATTER_TLS pTls;
    PPMEM_SCATTER ppMEMs = NULL;
    PBYTE pbData = NULL;
    if(!InitOnceExecuteOnce(&g_LeechRpcReadScatterTlsInitOnce, LeechRPC_ReadScatterTlsInit, NULL, NULL)) { return FALSE; }
    pTls = (PLEECHRPC_READSCATTER_TLS)TlsGetValue(g_dwLeechRpcReadScatterTlsIndex);
    if(!pTls) {
        if(!(pTls = (PLEECHRPC_READSCATTER_TLS)LocalAlloc(LMEM_ZEROINIT, sizeof(LEECHRPC_READSCATTER_TLS)))) { return FALSE; }
        if(!TlsSetValue(g_dwLeechRpcReadScatterTlsIndex, pTls)) {
            LocalFree(pTls);
            return FALSE;
        }
    }
    if(pTls->cbMEMs < cbMEMs) {
        if(!(ppMEMs = (PPMEM_SCATTER)LocalAlloc(0, cbMEMs))) { return FALSE; }
        LocalFree(pTls->ppMEMs);
        pTls->ppMEMs = ppMEMs;
        pTls->cbMEMs = cbMEMs;
    }
    if(pTls->cbData < cbMax) {
        if(!(pbData = (PBYTE)LocalAlloc(0, cbMax))) { return FALSE; }
        LocalFree(pTls->pbData);
        pTls->pbData = pbData;
        pTls->cbData = cbMax;
    }
    *pppMEMs = pTls->ppMEMs;
    *ppbData = pTls->pbData;
    return TRUE;
}
#else
_Success_(return)
static BOOL LeechRPC_ReadScatterEnsureTlsBuffers(_In_ DWORD cMEMs, _In_ DWORD cbMax, _Out_ PPMEM_SCATTER *pppMEMs, _Out_ PBYTE *ppbData)
{
    UNREFERENCED_PARAMETER(cMEMs);
    UNREFERENCED_PARAMETER(cbMax);
    UNREFERENCED_PARAMETER(pppMEMs);
    UNREFERENCED_PARAMETER(ppbData);
    return FALSE;
}
#endif


static VOID LeechRpc_LogReject(_In_ DWORD dwRpcClientID, _In_z_ const char *szReason)
{
    CHAR szTime[32];
    LeechSvc_GetTimeStamp(szTime);
    LeechRpc_ServerLocalLog("[%s] REJECT: Client ID %08X %s\n", szTime, dwRpcClientID, szReason);
}

static BOOL LeechRpc_IsPmemDeviceRequest(_In_ const LC_CONFIG *pCfg)
{
    if(!pCfg->szDevice[0]) {
        return TRUE;
    }
    return 0 == _strnicmp("pmem", pCfg->szDevice, 4);
}

static BOOL LeechRpc_IsCommandAllowed(_In_ QWORD fCommand)
{
    switch(fCommand) {
        case LC_CMD_STATISTICS_GET:
        case LC_CMD_MEMMAP_GET:
        case LC_CMD_MEMMAP_SET:
        case LC_CMD_MEMMAP_GET_STRUCT:
        case LC_CMD_MEMMAP_SET_STRUCT:
            return TRUE;
        default:
            return FALSE;
    }
}

//-----------------------------------------------------------------------------
// CLIENT TRACK / KEEPALIVE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

_Success_(return != NULL)
HANDLE LeechRPC_LcHandle_GetExisting(_In_ DWORD dwRpcClientID, _Out_opt_ PHANDLE* pphPP)
{
    DWORD i;
    HANDLE hLC = NULL;
    if(!dwRpcClientID) { return NULL; }
    EnterCriticalSection(&ctxLeechRpc.LockClientList);
    for(i = 0; i < LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS; i++) {
        if(ctxLeechRpc.ClientList[i].dwRpcClientID == dwRpcClientID) {
            ctxLeechRpc.ClientList[i].cActiveRequests++;
            ctxLeechRpc.ClientList[i].qwLastTickCount64 = GetTickCount64();
            if(pphPP) { *pphPP = &ctxLeechRpc.ClientList[i].hPP; }
            hLC = ctxLeechRpc.ClientList[i].hLC;
            break;
        }
    }
    LeaveCriticalSection(&ctxLeechRpc.LockClientList);
    return hLC;
}

_Success_(return)
BOOL LeechRPC_LcHandle_New(_In_ DWORD dwRpcClientID, _In_ HANDLE hLC)
{
    DWORD i;
    QWORD qwNow = GetTickCount64();
    EnterCriticalSection(&ctxLeechRpc.LockClientList);
    for(i = 0; i < LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS; i++) {
        if(!ctxLeechRpc.ClientList[i].dwRpcClientID) {
            ctxLeechRpc.ClientList[i].hLC = hLC;
            ctxLeechRpc.ClientList[i].dwRpcClientID = dwRpcClientID;
            ctxLeechRpc.ClientList[i].cActiveRequests = 0;
            ctxLeechRpc.ClientList[i].qwLastTickCount64 = qwNow;
            ctxLeechRpc.ClientList[i].qwConnectTickCount64 = qwNow;
#if LEECHRPC_SERVER_PERF_STATS_ENABLE
            if(!ctxLeechRpc.Perf.fStarted) {
                ctxLeechRpc.Perf.fStarted = TRUE;
                ctxLeechRpc.Perf.qwStartTickCount64 = qwNow;
                ctxLeechRpc.Perf.qwLastLogTickCount64 = 0;
            }
            ctxLeechRpc.Perf.cOpen++;
#endif
            LeaveCriticalSection(&ctxLeechRpc.LockClientList);
            return TRUE;
        }
    }
    LeaveCriticalSection(&ctxLeechRpc.LockClientList);
    return FALSE;
}

VOID LeechRPC_LcHandle_Return(_In_opt_ HANDLE hLC, _In_ DWORD dwRpcClientID)
{
    DWORD i;
    if(!hLC) { return; }
    for(i = 0; i < LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS; i++) {
        if((ctxLeechRpc.ClientList[i].hLC == hLC) && (ctxLeechRpc.ClientList[i].dwRpcClientID == dwRpcClientID)) {
            EnterCriticalSection(&ctxLeechRpc.LockClientList);
            ctxLeechRpc.ClientList[i].cActiveRequests--;
            LeaveCriticalSection(&ctxLeechRpc.LockClientList);
            break;
        }
    }
}

VOID LeechRPC_LcHandle_Close(_In_ DWORD dwRpcClientID, _In_ BOOL fReasonTimeout)
{
    DWORD i;
    CHAR szTime[32];
    HANDLE hLC = NULL, hPP = NULL;
    EnterCriticalSection(&ctxLeechRpc.LockClientList);
    for(i = 0; i < LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS; i++) {
        if(ctxLeechRpc.ClientList[i].dwRpcClientID == dwRpcClientID) {
            while(ctxLeechRpc.ClientList[i].cActiveRequests) {
                LeaveCriticalSection(&ctxLeechRpc.LockClientList);
                Sleep(10);
                EnterCriticalSection(&ctxLeechRpc.LockClientList);
            }
            hLC = ctxLeechRpc.ClientList[i].hLC;
            hPP = ctxLeechRpc.ClientList[i].hPP;
            ctxLeechRpc.ClientList[i].hLC = NULL;
            ctxLeechRpc.ClientList[i].hPP = NULL;
            ctxLeechRpc.ClientList[i].dwRpcClientID = 0;
            ctxLeechRpc.ClientList[i].qwLastTickCount64 = 0;
            ctxLeechRpc.ClientList[i].qwConnectTickCount64 = 0;
#if LEECHRPC_SERVER_PERF_STATS_ENABLE
            if(ctxLeechRpc.Perf.fStarted) {
                ctxLeechRpc.Perf.cClose++;
            }
#endif
            break;
        }
    }
    LeaveCriticalSection(&ctxLeechRpc.LockClientList);
    if(hPP) {
        LeechAgent_ProcParent_Close(hPP);
    }
    if(hLC) {
        LcClose(hLC);
        LeechSvc_GetTimeStamp(szTime);
        if(fReasonTimeout) {
            LeechRpc_ServerLocalLog("[%s] CLOSE: Client ID %08X timeout after %is.\n", szTime, dwRpcClientID, (LEECHAGENT_CLIENTKEEPALIVE_TIMEOUT_MS / 1000));
        } else {
            LeechRpc_ServerLocalLog("[%s] CLOSE: Client ID %08X\n", szTime, dwRpcClientID);
        }
    }
}

VOID LeechRPC_LcHandle_CloseAll()
{
    DWORD i;
    for(i = 0; i < LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS; i++) {
        if(ctxLeechRpc.ClientList[i].dwRpcClientID) {
            LeechRPC_LcHandle_Close(ctxLeechRpc.ClientList[i].dwRpcClientID, FALSE);
        }
    }
}

VOID LeechRPC_LcHandle_InactivityWatcherThread(PVOID pv)
{
    DWORD i;
    ctxLeechRpc.fInactivityWatcherThread = TRUE;
    ctxLeechRpc.fInactivityWatcherThreadIsRunning = TRUE;
    while(ctxLeechRpc.fInactivityWatcherThread) {
        Sleep(1000);
        for(i = 0; i < LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS; i++) {
            if(ctxLeechRpc.ClientList[i].qwLastTickCount64 && (ctxLeechRpc.ClientList[i].qwLastTickCount64 + LEECHAGENT_CLIENTKEEPALIVE_TIMEOUT_MS < GetTickCount64())) {
                LeechRPC_LcHandle_Close(ctxLeechRpc.ClientList[i].dwRpcClientID, TRUE);
            }
        }
        LeechRpc_PerfLogSnapshot(FALSE);
    }
    ctxLeechRpc.fInactivityWatcherThreadIsRunning = FALSE;
}



//-----------------------------------------------------------------------------
// GENERAL FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID LeechRpcOnLoadInitialize()
{
    ctxLeechRpc.fValid = TRUE;
    LeechRPC_CompressInitialize(&ctxLeechRpc.Compress);
    InitializeCriticalSection(&ctxLeechRpc.LockClientList);
    InitializeCriticalSection(&g_LeechRpcResponsePoolLock);
    g_fLeechRpcResponsePoolInit = TRUE;
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LeechRPC_LcHandle_InactivityWatcherThread, NULL, 0, NULL);
}

VOID LeechRpcOnUnloadClose()
{
    DWORD i;
    ctxLeechRpc.fInactivityWatcherThread = FALSE;
    while(ctxLeechRpc.fInactivityWatcherThreadIsRunning) {
        SwitchToThread();
    }
    LeechRPC_LcHandle_CloseAll();
    LeechRpc_PerfLogSnapshot(TRUE);
    DeleteCriticalSection(&ctxLeechRpc.LockClientList);
    if(g_fLeechRpcResponsePoolInit) {
        DWORD iLayout;
        for(iLayout = 0; iLayout < LEECHRPC_RESPPOOL_LAYOUT_MAX; iLayout++) {
            for(i = 0; i < LEECHRPC_RESPPOOL_BUCKETS; i++) {
                while(g_LeechRpcResponsePoolHead[iLayout][i]) {
                    PLEECHRPC_RESPONSE_POOL_HDR pHdr = g_LeechRpcResponsePoolHead[iLayout][i];
                    g_LeechRpcResponsePoolHead[iLayout][i] = pHdr->Flink;
                    LocalFree(pHdr);
                }
                g_cLeechRpcResponsePoolCount[iLayout][i] = 0;
            }
        }
        DeleteCriticalSection(&g_LeechRpcResponsePoolLock);
        g_fLeechRpcResponsePoolInit = FALSE;
    }
    LeechRPC_CompressClose(&ctxLeechRpc.Compress);
    ZeroMemory(&ctxLeechRpc, sizeof(LEECHRPC_SERVER_CONTEXT));
}

error_status_t LeechRpc_CommandReadScatter(_In_ HANDLE hLC, _In_ PLEECHRPC_MSG_BIN pReq, long *pcbOut, byte **ppbOut)
{
    BOOL fOK;
    BOOL fUseTlsBuffers = FALSE;
    PLEECHRPC_MSG_BIN pRsp = NULL;
    PMEM_SCATTER pMEM_Src, pMEM_Dst;
    PPMEM_SCATTER ppMEMs = NULL;
    DWORD i, cMEMs, cbMax;
    PBYTE pbDataDst;
    DWORD cbDataOffset = 0, cbRead = 0;
    DWORD cbRsp;
    cMEMs = (DWORD)pReq->qwData[0];
    cbMax = (DWORD)pReq->qwData[1];
    // 1: verify incoming result
    fOK = (pReq->cb == cMEMs * sizeof(MEM_SCATTER)) && (cMEMs <= 0x2000) && (cbMax <= (cMEMs << 12));
    if(!fOK) { goto fail; }
    // 2: allocate response once and point scatter buffers directly into it.
    fUseTlsBuffers = LeechRPC_ReadScatterEnsureTlsBuffers(cMEMs, 0, &ppMEMs, &pbDataDst);
    if(!fUseTlsBuffers && !(ppMEMs = LocalAlloc(LMEM_ZEROINIT, cMEMs * sizeof(PMEM_SCATTER)))) { goto fail; }
    cbRsp = sizeof(LEECHRPC_MSG_BIN) + cMEMs * sizeof(MEM_SCATTER) + cbMax;
    if(!(pRsp = (PLEECHRPC_MSG_BIN)LeechRpc_ServerResponseAllocFrameReady(cbRsp))) { goto fail; }
    ZeroMemory(pRsp, sizeof(LEECHRPC_MSG_BIN));
    pRsp->cbMsg = cbRsp;
    pRsp->dwMagic = LEECHRPC_MSGMAGIC;
    pRsp->fMsgResult = TRUE;
    pRsp->tpMsg = LEECHRPC_MSGTYPE_READSCATTER_RSP;
    pRsp->flags = LEECHRPC_FLAG_READSCATTER_PADDED;
    memcpy(pRsp->pb, pReq->pb, pReq->cb);
    pRsp->cb = pReq->cb + cbMax;
    pRsp->qwData[0] = cMEMs;
    pMEM_Dst = (PMEM_SCATTER)pRsp->pb;
    pbDataDst = pRsp->pb + pReq->cb;
    for(i = 0; i < cMEMs; i++) {
        if((pMEM_Dst->version != MEM_SCATTER_VERSION) || (pMEM_Dst->cb > 0x1000)) { goto fail; }
        pMEM_Dst->pb = pbDataDst + cbDataOffset;
        cbDataOffset += pMEM_Dst->cb;
        ppMEMs[i] = pMEM_Dst;
        pMEM_Dst = pMEM_Dst + 1;
    }
    if(cbDataOffset > cbMax) { goto fail; }
    // 3: call & count read data
    LcReadScatter(hLC, cMEMs, ppMEMs);
    pMEM_Src = (PMEM_SCATTER)pRsp->pb;
    for(i = 0, cbRead = 0; i < cMEMs; i++) {
        if(pMEM_Src->f) {
            cbRead += pMEM_Src->cb;
        }
        pMEM_Src = pMEM_Src + 1;
    }
    pRsp->qwData[0] = cMEMs;
    pRsp->cbDecompress = 0;
    *pcbOut = pRsp->cbMsg;
    *ppbOut = (PBYTE)pRsp;
    LeechRpc_PerfOnReadScatter(cMEMs, cbDataOffset, cbRead, TRUE);
    if(!fUseTlsBuffers) {
        LocalFree(ppMEMs);
    }
    return 0;
fail:
    *pcbOut = 0;
    *ppbOut = NULL;
    LeechRpc_PerfOnReadScatter(cMEMs, cbDataOffset, 0, FALSE);
    LeechRpc_ServerResponseFree((PBYTE)pRsp);
    if(!fUseTlsBuffers) {
        LocalFree(ppMEMs);
    }
    return 1;
}
error_status_t LeechRpc_CommandWriteScatter(_In_ HANDLE hLC, _In_ PLEECHRPC_MSG_BIN pReq, long *pcbOut, byte **ppbOut)
{
    PBOOL pfRsp;
    PLEECHRPC_MSG_BIN pRsp = NULL;
    PMEM_SCATTER pMEM, pMEMs;
    PPMEM_SCATTER ppMEMs = NULL;
    DWORD i, cMEMs, cbRsp;
    PBYTE pbData = NULL;
    cMEMs = (DWORD)pReq->qwData[0];
    // 1: verify and fixup incoming data 
    pMEMs = (PMEM_SCATTER)pReq->pb;
    pbData = pReq->pb + cMEMs * sizeof(MEM_SCATTER);
    if(pReq->cb != cMEMs * (sizeof(MEM_SCATTER) + 0x1000)) { goto fail; }
    if(!(ppMEMs = LocalAlloc(LMEM_ZEROINIT, cMEMs * sizeof(PMEM_SCATTER)))) { goto fail; }
    for(i = 0; i < cMEMs; i++) {
        ppMEMs[i] = pMEM = pMEMs + i;
        if((pMEM->cb > 0x1000) || (pMEM->iStack > MEM_SCATTER_STACK_SIZE - 4)) { goto fail; }
        pMEM->pb = pbData;
        pbData += pMEM->cb;
    }
    // 2: call & return result
    LcWriteScatter(hLC, cMEMs, ppMEMs);
    cbRsp = sizeof(LEECHRPC_MSG_BIN) + cMEMs * sizeof(BOOL);
    if(!(pRsp = (PLEECHRPC_MSG_BIN)LeechRpc_ServerResponseAlloc(cbRsp))) { goto fail; }
    ZeroMemory(pRsp, cbRsp);
    pRsp->cbMsg = cbRsp;
    pRsp->dwMagic = LEECHRPC_MSGMAGIC;
    pRsp->fMsgResult = TRUE;
    pRsp->tpMsg = LEECHRPC_MSGTYPE_WRITESCATTER_RSP;
    pRsp->cb = cMEMs * sizeof(BOOL);
    pfRsp = (PBOOL)pRsp->pb;
    for(i = 0; i < cMEMs; i++) {
        pfRsp[i] = pMEMs[i].f;
    }
    pRsp->qwData[0] = cMEMs;
    pRsp->cbDecompress = 0;
    *pcbOut = pRsp->cbMsg;
    *ppbOut = (PBYTE)pRsp;
    LocalFree(ppMEMs);
    return 0;
fail:
    *pcbOut = 0;
    *ppbOut = NULL;
    LeechRpc_ServerResponseFree((PBYTE)pRsp);
    LocalFree(ppMEMs);
    return (error_status_t)-1;
}

/*
* Transfer commands/data to/from the remote service (if it exists).
* NB! USER-FREE: ppbDataOut (LocalFree)
* -- hLC
* -- phPP
* -- fOption = the command as specified by LC_CMD_AGENT_*
* -- cbDataIn
* -- pbDataIn
* -- ppbDataOut =  ptr to receive function allocated output - must be LocalFree'd by caller!
* -- pcbDataOut = ptr to receive length of *pbDataOut.
* -- return
*/
_Success_(return)
BOOL LeechRpc_CommandAgent(_In_ HANDLE hLC, _In_opt_ PHANDLE phPP, _In_ QWORD fOption, _In_ DWORD cbDataIn, _In_reads_(cbDataIn) PBYTE pbDataIn, _Out_writes_opt_(*pcbDataOut) PBYTE *ppbDataOut, _Out_opt_ PDWORD pcbDataOut)
{
    if(ppbDataOut) { *ppbDataOut = NULL; }
    if(pcbDataOut) { *pcbDataOut = 0; }
    switch(fOption & 0xffffffff00000000) {
        case LC_CMD_AGENT_EXEC_PYTHON:
            return LeechAgent_ProcParent_ExecPy(hLC, fOption & 0xffffffff, pbDataIn, cbDataIn, ppbDataOut, pcbDataOut);
        case LC_CMD_AGENT_EXIT_PROCESS:
            ExitProcess(fOption & 0xffffffff);
            return FALSE;   // not reached ...
        case LC_CMD_AGENT_VFS_INITIALIZE:
            if(!phPP) { return FALSE; }
            return LeechAgent_ProcParent_VfsInitialize(hLC, phPP, pbDataIn, cbDataIn, ppbDataOut, pcbDataOut);
        case LC_CMD_AGENT_VFS_CONSOLE:
            if(!phPP) { return FALSE; }
            return LeechAgent_ProcParent_VfsConsole(hLC, phPP, ppbDataOut, pcbDataOut);
        case LC_CMD_AGENT_VFS_LIST:
            if(!phPP) { return FALSE; }
            return LeechAgent_ProcParent_VfsCMD(hLC, phPP, LEECHAGENT_PROC_CMD_VFS_LIST, pbDataIn, cbDataIn, ppbDataOut, pcbDataOut);
        case LC_CMD_AGENT_VFS_READ:
            if(!phPP) { return FALSE; }
            return LeechAgent_ProcParent_VfsCMD(hLC, phPP, LEECHAGENT_PROC_CMD_VFS_READ, pbDataIn, cbDataIn, ppbDataOut, pcbDataOut);
        case LC_CMD_AGENT_VFS_WRITE:
            if(!phPP) { return FALSE; }
            return LeechAgent_ProcParent_VfsCMD(hLC, phPP, LEECHAGENT_PROC_CMD_VFS_WRITE, pbDataIn, cbDataIn, ppbDataOut, pcbDataOut);
        case LC_CMD_AGENT_VFS_OPT_GET:
            if(!phPP) { return FALSE; }
            return LeechAgent_ProcParent_VfsCMD(hLC, phPP, LEECHAGENT_PROC_CMD_VFS_OPT_GET, pbDataIn, cbDataIn, ppbDataOut, pcbDataOut);
        case LC_CMD_AGENT_VFS_OPT_SET:
            if(!phPP) { return FALSE; }
            return LeechAgent_ProcParent_VfsCMD(hLC, phPP, LEECHAGENT_PROC_CMD_VFS_OPT_SET, pbDataIn, cbDataIn, ppbDataOut, pcbDataOut);
        default:
            return FALSE;
    }
}

error_status_t LeechRpc_CommandOpen(_In_ PLEECHRPC_MSG_OPEN pReq, long *pcbOut, byte **ppbOut)
{
    DWORD cbRsp;
    CHAR szTime[32];
    HANDLE hLC = NULL;
    PLEECHRPC_MSG_OPEN pRsp = NULL;
    PLC_CONFIG_ERRORINFO pLcErrorInfo = NULL;
    LC_CONFIG cfg = pReq->cfg;
    cfg.pfn_printf_opt = NULL;
    ZeroMemory(cfg.szRemote, sizeof(cfg.szRemote));
    if(!cfg.szDevice[0]) {
        strcpy_s(cfg.szDevice, sizeof(cfg.szDevice), "pmem");
    }

    // Force a clean slate for pmem sessions before opening a new one.
    LeechRPC_LcHandle_CloseAll();

    if(LeechRpc_IsPmemDeviceRequest(&cfg)) {
        hLC = LcCreateEx(&cfg, &pLcErrorInfo);
    } else {
        LeechRpc_LogReject(pReq->dwRpcClientID, "OPEN rejected (non-pmem device).");
    }
    if(hLC && !LeechRPC_LcHandle_New(pReq->dwRpcClientID, hLC)) {
        LcClose(hLC);
        hLC = NULL;
    }
    pReq->cfg.pfn_printf_opt = NULL;
    cbRsp = sizeof(LEECHRPC_MSG_OPEN) + (pLcErrorInfo ? (pLcErrorInfo->cbStruct - sizeof(LC_CONFIG_ERRORINFO)) : 0);
    if(!(pRsp = (PLEECHRPC_MSG_OPEN)LeechRpc_ServerResponseAlloc(cbRsp))) {
        *pcbOut = 0;
        *ppbOut = NULL;
        return (error_status_t)-1;
    }
    ZeroMemory(pRsp, cbRsp);
    pRsp->cbMsg = cbRsp;
    pRsp->dwMagic = LEECHRPC_MSGMAGIC;
    pRsp->fMsgResult = TRUE;
    pRsp->fValidOpen = hLC ? TRUE : FALSE;
    if(pRsp->fValidOpen) {
        LeechSvc_GetTimeStamp(szTime);
        LeechRpc_ServerLocalLog("[%s] OPEN: Client ID %08X\n", szTime, pReq->dwRpcClientID);
        memcpy(&pRsp->cfg, &cfg, sizeof(LC_CONFIG));
        pRsp->cfg.fRemoteDisableCompress = TRUE;
        pRsp->flags = 0;
    }
    if(pLcErrorInfo) {
        memcpy(&pRsp->errorinfo, pLcErrorInfo, pLcErrorInfo->cbStruct);
    }
    pRsp->tpMsg = LEECHRPC_MSGTYPE_OPEN_RSP;
    *pcbOut = pRsp->cbMsg;
    *ppbOut = (PBYTE)pRsp;
    LocalFree(pLcErrorInfo);
    return 0;
}


static BOOL LeechRpc_CommandPerf(
    _Out_ long *pcbOut,
    _Out_ byte **ppbOut)
{
    PLEECHRPC_MSG_BIN pRspBin = NULL;
    LEECHRPC_PERF_SNAPSHOT Perf = { 0 };
    Perf.dwVersion = 1;
#if LEECHRPC_SERVER_PERF_STATS_ENABLE
    LeechRpc_PerfLogSnapshot(TRUE);
    EnterCriticalSection(&ctxLeechRpc.LockClientList);
    if(ctxLeechRpc.Perf.fStarted) {
        Perf.cActiveClients = ctxLeechRpc.Perf.cActiveClientsLast;
        Perf.qwElapsedMs = ctxLeechRpc.Perf.qwElapsedMsLast;
        Perf.cReqTotal = ctxLeechRpc.Perf.cReqTotal;
        Perf.cReqFail = ctxLeechRpc.Perf.cReqFail;
        Perf.cbInTotal = ctxLeechRpc.Perf.cbInTotal;
        Perf.cbOutTotal = ctxLeechRpc.Perf.cbOutTotal;
        Perf.cReadScatterMemTotal = ctxLeechRpc.Perf.cReadScatterMemTotal;
        Perf.cbReadReqTotal = ctxLeechRpc.Perf.cbReadReqTotal;
        Perf.cbReadRspTotal = ctxLeechRpc.Perf.cbReadRspTotal;
        Perf.cReqPerSec = ctxLeechRpc.Perf.cReqPerSecLast;
        Perf.cbInPerSec = ctxLeechRpc.Perf.cbInPerSecLast;
        Perf.cbOutPerSec = ctxLeechRpc.Perf.cbOutPerSecLast;
        Perf.cActiveRequests = ctxLeechRpc.Perf.cActiveRequestsLast;
        Perf.qwOldestConnAgeMs = ctxLeechRpc.Perf.qwOldestConnAgeMsLast;
    }
    LeaveCriticalSection(&ctxLeechRpc.LockClientList);
#endif
    pRspBin = (PLEECHRPC_MSG_BIN)LeechRpc_ServerResponseAlloc(sizeof(LEECHRPC_MSG_BIN) + sizeof(LEECHRPC_PERF_SNAPSHOT));
    if(!pRspBin) {
        *pcbOut = 0;
        *ppbOut = NULL;
        return FALSE;
    }
    ZeroMemory(pRspBin, sizeof(LEECHRPC_MSG_BIN) + sizeof(LEECHRPC_PERF_SNAPSHOT));
    pRspBin->cbMsg = sizeof(LEECHRPC_MSG_BIN) + sizeof(LEECHRPC_PERF_SNAPSHOT);
    pRspBin->dwMagic = LEECHRPC_MSGMAGIC;
    pRspBin->fMsgResult = TRUE;
    pRspBin->tpMsg = LEECHRPC_MSGTYPE_PERF_RSP;
    pRspBin->cbDecompress = 0;
    pRspBin->cb = sizeof(LEECHRPC_PERF_SNAPSHOT);
    memcpy(pRspBin->pb, &Perf, sizeof(LEECHRPC_PERF_SNAPSHOT));
    *pcbOut = pRspBin->cbMsg;
    *ppbOut = (byte*)pRspBin;
    return TRUE;
}
error_status_t LeechRpc_ReservedSubmitCommand(
    /* [in] */ handle_t hBinding,
    /* [in] */ long cbIn,
    /* [size_is][in] */ byte *pbIn,
    /* [out] */ long *pcbOut,
    /* [size_is][size_is][out] */ byte **ppbOut)
{
    HANDLE hLC = NULL, *phPP = NULL;
    BOOL fTMP = FALSE;
    DWORD cbTMP = 0;
    PBYTE pbTMP = NULL;
    BOOL fFreeReqBin = FALSE;
    error_status_t status = 0;
    PLEECHRPC_MSG_HDR pReq = NULL;
    PLEECHRPC_MSG_HDR pRsp = NULL;
    PLEECHRPC_MSG_OPEN pReqOpen = NULL;
    PLEECHRPC_MSG_DATA pReqData = NULL;
    PLEECHRPC_MSG_DATA pRspData = NULL;
    PLEECHRPC_MSG_BIN pReqBin = NULL;
    PLEECHRPC_MSG_BIN pRspBin = NULL;
    DWORD cbInSafe = (cbIn > 0) ? (DWORD)cbIn : 0;
    // 1: sanity checks in incoming data
    if(!ctxLeechRpc.fValid) { return status; }
    if(cbIn < sizeof(LEECHRPC_MSG_HDR)) { return status; }
    pReq = (PLEECHRPC_MSG_HDR)pbIn;
    if((pReq->dwMagic != LEECHRPC_MSGMAGIC) || (pReq->tpMsg > LEECHRPC_MSGTYPE_MAX) || (pReq->cbMsg < sizeof(LEECHRPC_MSG_HDR))) { return status; }
    if((pReq->tpMsg != LEECHRPC_MSGTYPE_PING_REQ) && !Activation_IsAuthorized()) {
        LeechRpc_LogReject(pReq->dwRpcClientID, "REQUEST rejected (activation required).");
        goto fail;
    }
    // OPEN is treated as a fresh session request; don't pin an existing handle
    // here to avoid blocking global session recycle in open path.
    if(pReq->tpMsg != LEECHRPC_MSGTYPE_OPEN_REQ) {
        hLC = LeechRPC_LcHandle_GetExisting(pReq->dwRpcClientID, &phPP);
    }
    if(!hLC && !((pReq->tpMsg == LEECHRPC_MSGTYPE_PING_REQ) || (pReq->tpMsg == LEECHRPC_MSGTYPE_OPEN_REQ) || (pReq->tpMsg == LEECHRPC_MSGTYPE_CLOSE_REQ) || (pReq->tpMsg == LEECHRPC_MSGTYPE_PERF_REQ))) { goto fail; }
    switch(pReq->tpMsg) {
        case LEECHRPC_MSGTYPE_PING_REQ:
        case LEECHRPC_MSGTYPE_CLOSE_REQ:
        case LEECHRPC_MSGTYPE_KEEPALIVE_REQ:
        case LEECHRPC_MSGTYPE_PERF_REQ:
            if(pReq->cbMsg != sizeof(LEECHRPC_MSG_HDR)) { goto fail; }
            break;
        case LEECHRPC_MSGTYPE_OPEN_REQ:
            if(pReq->cbMsg != sizeof(LEECHRPC_MSG_OPEN)) { goto fail; }
            pReqOpen = (PLEECHRPC_MSG_OPEN)pReq;
            break;
        case LEECHRPC_MSGTYPE_GETOPTION_REQ:
        case LEECHRPC_MSGTYPE_SETOPTION_REQ:
            if(pReq->cbMsg != sizeof(LEECHRPC_MSG_DATA)) { goto fail; }
            pReqData = (PLEECHRPC_MSG_DATA)pReq;
            break;
        case LEECHRPC_MSGTYPE_READSCATTER_REQ:
        case LEECHRPC_MSGTYPE_WRITESCATTER_REQ:
        case LEECHRPC_MSGTYPE_COMMAND_REQ:
            if(pReq->cbMsg != sizeof(LEECHRPC_MSG_BIN) + ((PLEECHRPC_MSG_BIN)pReq)->cb) { goto fail; }
            if(((PLEECHRPC_MSG_BIN)pReq)->cbDecompress) {
                if(!LeechRPC_Decompress(&ctxLeechRpc.Compress, (PLEECHRPC_MSG_BIN)pReq, &pReqBin)) { goto fail; }
                fFreeReqBin = TRUE; // data allocated by decompress function must be free'd
            } else {
                pReqBin = ((PLEECHRPC_MSG_BIN)pReq);
            }
            break;
        default:
            goto fail;
    }
    // 2: dispatch
    switch(pReq->tpMsg) {
        case LEECHRPC_MSGTYPE_PING_REQ:
            if(!(pRsp = (PLEECHRPC_MSG_HDR)LeechRpc_ServerResponseAlloc(sizeof(LEECHRPC_MSG_HDR)))) { goto fail; }
            pRsp->cbMsg = sizeof(LEECHRPC_MSG_HDR);
            pRsp->dwMagic = LEECHRPC_MSGMAGIC;
            pRsp->fMsgResult = TRUE;
            pRsp->tpMsg = LEECHRPC_MSGTYPE_PING_RSP;
            *pcbOut = pRsp->cbMsg;
            *ppbOut = (PBYTE)pRsp;
            goto finish;
        case LEECHRPC_MSGTYPE_KEEPALIVE_REQ:
            if(!(pRsp = (PLEECHRPC_MSG_HDR)LeechRpc_ServerResponseAlloc(sizeof(LEECHRPC_MSG_HDR)))) { goto fail; }
            pRsp->cbMsg = sizeof(LEECHRPC_MSG_HDR);
            pRsp->dwMagic = LEECHRPC_MSGMAGIC;
            pRsp->fMsgResult = TRUE;
            pRsp->tpMsg = LEECHRPC_MSGTYPE_KEEPALIVE_RSP;
            *pcbOut = pRsp->cbMsg;
            *ppbOut = (PBYTE)pRsp;
            goto finish;
        case LEECHRPC_MSGTYPE_PERF_REQ:
            if(!LeechRpc_CommandPerf(pcbOut, ppbOut)) { goto fail; }
            goto finish;
        case LEECHRPC_MSGTYPE_OPEN_REQ:
            if(pReqOpen) {
                LeechRpc_CommandOpen(pReqOpen, pcbOut, ppbOut);
            }
            goto finish;
        case LEECHRPC_MSGTYPE_READSCATTER_REQ:
            status = LeechRpc_CommandReadScatter(hLC, pReqBin, pcbOut, ppbOut);
            if(fFreeReqBin) { LocalFree(pReqBin); pReqBin = NULL; } // only free locally allocated decompressed bindata
            goto finish;
        case LEECHRPC_MSGTYPE_WRITESCATTER_REQ:
            LeechRpc_LogReject(pReq->dwRpcClientID, "WRITESCATTER rejected (pmem-readonly).");
            if(fFreeReqBin) { LocalFree(pReqBin); pReqBin = NULL; } // only free locally allocated decompressed bindata
            goto fail;
        case LEECHRPC_MSGTYPE_CLOSE_REQ:
            LeechRPC_LcHandle_Return(hLC, pReq->dwRpcClientID);
            hLC = NULL;
            LeechRPC_LcHandle_Close(pReq->dwRpcClientID, FALSE);
            if(!(pRsp = (PLEECHRPC_MSG_HDR)LeechRpc_ServerResponseAlloc(sizeof(LEECHRPC_MSG_HDR)))) { goto fail; }
            pRsp->cbMsg = sizeof(LEECHRPC_MSG_HDR);
            pRsp->dwMagic = LEECHRPC_MSGMAGIC;
            pRsp->fMsgResult = TRUE;
            pRsp->tpMsg = LEECHRPC_MSGTYPE_CLOSE_RSP;
            *pcbOut = pRsp->cbMsg;
            *ppbOut = (PBYTE)pRsp;
            goto finish;
        case LEECHRPC_MSGTYPE_GETOPTION_REQ:
            if(!(pRspData = (PLEECHRPC_MSG_DATA)LeechRpc_ServerResponseAlloc(sizeof(LEECHRPC_MSG_DATA)))) { goto fail; }
            pRspData->cbMsg = sizeof(LEECHRPC_MSG_DATA);
            pRspData->dwMagic = LEECHRPC_MSGMAGIC;
            pRspData->fMsgResult = pReqData && LcGetOption(hLC, pReqData->qwData[0], &pRspData->qwData[0]);
            pRspData->tpMsg = LEECHRPC_MSGTYPE_GETOPTION_RSP;
            *pcbOut = pRspData->cbMsg;
            *ppbOut = (PBYTE)pRspData;
            goto finish;
        case LEECHRPC_MSGTYPE_SETOPTION_REQ:
            LeechRpc_LogReject(pReq->dwRpcClientID, "SETOPTION rejected (pmem-only).");
            goto fail;
        case LEECHRPC_MSGTYPE_COMMAND_REQ:
            if((pReqBin->qwData[0] >> 63) || !LeechRpc_IsCommandAllowed(pReqBin->qwData[0])) {
                LeechRpc_LogReject(pReq->dwRpcClientID, "COMMAND rejected (pmem-only).");
                goto fail;
            }
            fTMP = LcCommand(hLC, pReqBin->qwData[0], pReqBin->cb, pReqBin->pb, &pbTMP, &cbTMP);
            if(!fTMP) { cbTMP = 0; }
            if(!(pRspBin = (PLEECHRPC_MSG_BIN)LeechRpc_ServerResponseAlloc(sizeof(LEECHRPC_MSG_BIN) + cbTMP))) {
                goto fail;
            }
            ZeroMemory(pRspBin, sizeof(LEECHRPC_MSG_BIN) + cbTMP);
            pRspBin->fMsgResult = fTMP;
            pRspBin->cb = cbTMP;
            memcpy(pRspBin->pb, pbTMP, cbTMP);
            pbTMP = LocalFree(pbTMP);
            pRspBin->tpMsg = LEECHRPC_MSGTYPE_COMMAND_RSP;
            pRspBin->dwMagic = LEECHRPC_MSGMAGIC;
            pRspBin->cbMsg = sizeof(LEECHRPC_MSG_BIN) + pRspBin->cb;
            pRspBin->cbDecompress = 0;
            *pcbOut = pRspBin->cbMsg;
            *ppbOut = (PBYTE)pRspBin;
            if(fFreeReqBin) { LocalFree(pReqBin); pReqBin = NULL; } // only free locally allocated decompressed bindata
            goto finish;
        default:
            goto fail;
    }
finish:
    if(pReq && pcbOut && ppbOut && *ppbOut && (*pcbOut >= sizeof(LEECHRPC_MSG_HDR))) {
        PLEECHRPC_MSG_HDR pRspHdr = (PLEECHRPC_MSG_HDR)(*ppbOut);
        pRspHdr->dwMagic = LEECHRPC_MSGMAGIC;
        pRspHdr->dwRequestID = pReq->dwRequestID;
        pRspHdr->dwRpcClientID = pReq->dwRpcClientID;
        pRspHdr->flags |= pReq->flags;
        if(!pRspHdr->cbMsg) {
            pRspHdr->cbMsg = (DWORD)(*pcbOut);
        }
    }
    if(pReq) {
        DWORD cbOutSafe = (pcbOut && (*pcbOut > 0)) ? (DWORD)(*pcbOut) : 0;
        LeechRpc_PerfOnRequest(pReq->tpMsg, cbInSafe, cbOutSafe, TRUE);
        LeechRpc_PerfLogSnapshot(FALSE);
        LeechRPC_LcHandle_Return(hLC, pReq->dwRpcClientID);
    }
    return status;
fail:
    if(pReq) {
        LeechRpc_PerfOnRequest(pReq->tpMsg, cbInSafe, 0, FALSE);
        LeechRpc_PerfLogSnapshot(FALSE);
        LeechRPC_LcHandle_Return(hLC, pReq->dwRpcClientID);
    }
    if(fFreeReqBin) { LocalFree(pReqBin); pReqBin = NULL; } // only free locally allocated decompressed bindata
    *pcbOut = 0;
    *ppbOut = NULL;
    return (error_status_t)-1;
}

VOID LeechGRPC_ReservedSubmitCommand(_In_opt_ PVOID ctx, _In_ PBYTE pbIn, _In_ SIZE_T cbIn, _Out_ PBYTE *ppbOut, _Out_ SIZE_T *pcbOut)
{
    LeechRpc_ReservedSubmitCommand(NULL, (long)cbIn, pbIn, (long*)pcbOut, ppbOut);
}






