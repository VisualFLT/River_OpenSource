// leechagent.h : definitions related to the leech agent.
//
// (c) Ulf Frisk, 2018-2026
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __LEECHAGENT_H__
#define __LEECHAGENT_H__
#include <windows.h>

#define LEECHSVC_NAME           L"River"
#define LEECHSVC_DISPLAY_NAME   L"River Service"
#define LEECHSVC_DESCR_LONG     L"River remote service."
#define LEECHSVC_TCP_PORT_MSRPC L"30326"
#define LEECHSVC_TCP_PORT_GRPC  L"30327"
#define LEECHSVC_TCP_PORT_HTTP  L"4000"
#define SVC_ERROR				0x0000

#define LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS            0x40
#define LEECHAGENT_CLIENTKEEPALIVE_TIMEOUT_MS           5*1000    // keep short to recover quickly from abnormal disconnects
#define LEECHAGENT_CHILDPROCESS_TIMEOUT_MAX_MS      30*60*1000
#define LEECHAGENT_CHILDPROCESS_TIMEOUT_DEFAULT_MS   2*60*1000

typedef struct tdLEECHAGENT_CONFIG {
    BOOL fInstall;
    BOOL fUpdate;
    BOOL fUninstall;
    BOOL fInteractive;
    BOOL fInsecure;
    BOOL fChildProcess;
    BOOL fMSRPC;
    BOOL fgRPC;
    BOOL fHTTP;
    WCHAR wszRemote[MAX_PATH];
    WCHAR wszTcpPortMSRPC[0x10];
    WCHAR wszTcpPortGRPC[0x10];
    WCHAR wszTcpPortHTTP[0x10];
    HMODULE hModuleGRPC;
    struct {
        CHAR szCurrentDirectory[MAX_PATH];
        CHAR szTlsClientCaCert[MAX_PATH];
        CHAR szTlsServerP12[MAX_PATH];
        CHAR szTlsServerP12Pass[MAX_PATH];
        CHAR szListenAddress[MAX_PATH];
    } grpc;
} LEECHSVC_CONFIG, *PLEECHSVC_CONFIG;

typedef struct tdLEECHAGENT_REMOTE_ENTRY {
    BOOL f32;
    BOOL f64;
    LPWSTR wsz;
} LEECHAGENT_REMOTE_ENTRY, *PLEECHAGENT_REMOTE_ENTRY;

static LEECHAGENT_REMOTE_ENTRY g_REMOTE_FILES_REQUIRED[] = {
    {.f32 = TRUE,.f64 = TRUE,.wsz = L"leechcore.dll"},
    {.f32 = TRUE,.f64 = TRUE,.wsz = L"vcruntime140.dll"},
};
static LEECHAGENT_REMOTE_ENTRY g_REMOTE_FILES_OPTIONAL[] = {
    // 32/64-bit MemProcFS
    {.f32 = TRUE,.f64 = TRUE,.wsz = L"vmm.dll"},
    {.f32 = TRUE,.f64 = TRUE,.wsz = L"info.db"},
    {.f32 = TRUE,.f64 = TRUE,.wsz = L"libpdbcrust.dll"},
    {.f32 = TRUE,.f64 = TRUE,.wsz = L"vmmyara.dll"},
    {.f32 = TRUE,.f64 = TRUE,.wsz = L"dbghelp.dll"},
    {.f32 = TRUE,.f64 = TRUE,.wsz = L"symsrv.dll"},
    {.f32 = TRUE,.f64 = TRUE,.wsz = L"symsrv.yes"},
    // 64-bit MemProcFS Python
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"leechcorepyc.pyd"},
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"vmmpyc.pyd"},
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"memprocfs.py"},
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"vmmpyplugin.py"},
    // 64-bit HyperV saved state
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"leechcore_device_hvsavedstate.dll"},
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"vmsavedstatedumpprovider.dll"},
    // 64-bit HyperV HVMM (LiveCloudKd)
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"leechcore_device_hvmm.dll"},
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"LiveCloudKdSdk.dll"},
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"hvlib.dll"},
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"hvmm.sys"},
    // 32/64-bit FTDI driver (PCIe DMA FPGA)
    {.f32 = TRUE,.f64 = TRUE,.wsz = L"FTD3XX.dll"},
};
static LEECHAGENT_REMOTE_ENTRY g_REMOTE_DIRS_OPTIONAL[] = {
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"Plugins"},
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"Python"},
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"Yara"},
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"Cert"},
};

extern BOOL g_LeechAgent_IsService;

#endif /* __LEECHAGENT_H__ */
