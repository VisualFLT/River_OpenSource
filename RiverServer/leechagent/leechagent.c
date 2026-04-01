//	leechagent.c : Implementation the LeechAgent service related functionality.
//
// (c) Ulf Frisk, 2018-2026
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "leechagent.h"
#include "leechagent_svc.h"
#include "leechagent_rpc.h"
#include "leechagent_proc.h"
#include "leechrpc.h"
#include "util.h"
#include <stdio.h>
#include "leechagent_logging.h"
#include <strsafe.h>
#define SECURITY_WIN32
#include <security.h>

// Service/global mode flag; defined here, declared extern in leechagent.h.
BOOL g_LeechAgent_IsService = FALSE;

//-----------------------------------------------------------------------------
// MAIN, PARSE AND HELP FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Parse the application command line arguments.
* -- argc
* -- argv
* -- pConfig
* -- return
*/
_Success_(return)
BOOL LeechSvc_ParseArgs(_In_ DWORD argc, _In_ wchar_t *argv[], _In_ PLEECHSVC_CONFIG pConfig)
{
    LPWSTR wszOpt;
    LPSTR szCurrentDirectory;
    DWORD c = 0, i = 1;
    while(i < argc) {
        if((0 == _wcsicmp(argv[i], L"-install")) || (0 == _wcsicmp(argv[i], L"install"))) {
            pConfig->fInstall = TRUE;
            i++;
            continue;
        } else if((0 == _wcsicmp(argv[i], L"-uninstall")) || (0 == _wcsicmp(argv[i], L"uninstall")) || (0 == _wcsicmp(argv[i], L"delete"))) {
            pConfig->fUninstall = TRUE;
            i++;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-insecure")) {
            pConfig->fInsecure = TRUE;
            i++;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-interactive")) {
            pConfig->fInteractive = TRUE;
            i++;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-child")) {
            pConfig->fChildProcess = TRUE;
            return TRUE;
        } else if(0 == _wcsicmp(argv[i], L"-remoteinstall") && (i + 1 < argc)) {
            wcsncpy_s(pConfig->wszRemote, _countof(pConfig->wszRemote), argv[i + 1], _TRUNCATE);
            pConfig->fInstall = TRUE;
            i += 2;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-remoteuninstall") && (i + 1 < argc)) {
            wcsncpy_s(pConfig->wszRemote, _countof(pConfig->wszRemote), argv[i + 1], _TRUNCATE);
            pConfig->fUninstall = TRUE;
            i += 2;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-remoteupdate") && (i + 1 < argc)) {
            wcsncpy_s(pConfig->wszRemote, _countof(pConfig->wszRemote), argv[i + 1], _TRUNCATE);
            pConfig->fUpdate = TRUE;
            i += 2;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-z") && (i + 1 < argc)) {
            // DumpIt.exe emits -z <filename> in livekd mode - it has no meaning
            // to the LeechAgent - but should be considered valid - so skip it!
            i += 2;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-no-grpc")) {
            pConfig->fgRPC = FALSE;
            i++;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-http")) {
            pConfig->fHTTP = TRUE;
            i++;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-no-http")) {
            pConfig->fHTTP = FALSE;
            i++;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-grpc")) {
            pConfig->fgRPC = TRUE;
            i++;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-grpc-tls-p12") && (i + 1 < argc)) {
            wszOpt = argv[i + 1];
            szCurrentDirectory = "";
            if((wcslen(wszOpt) > 2) && (wszOpt[0] != '/') && (wszOpt[0] != '\\') && (wszOpt[1] != ':')) {
                szCurrentDirectory = pConfig->grpc.szCurrentDirectory;
            }
            _snprintf_s(pConfig->grpc.szTlsServerP12, _countof(pConfig->grpc.szTlsServerP12), _TRUNCATE, "%s%S", szCurrentDirectory, wszOpt);
            pConfig->fgRPC = TRUE;
            i += 2;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-grpc-client-ca") && (i + 1 < argc)) {
            wszOpt = argv[i + 1];
            szCurrentDirectory = "";
            if((wcslen(wszOpt) > 2) && (wszOpt[0] != '/') && (wszOpt[0] != '\\') && (wszOpt[1] != ':')) {
                szCurrentDirectory = pConfig->grpc.szCurrentDirectory;
            }
            _snprintf_s(pConfig->grpc.szTlsClientCaCert, _countof(pConfig->grpc.szTlsClientCaCert), _TRUNCATE, "%s%S", szCurrentDirectory, wszOpt);
            pConfig->fgRPC = TRUE;
            i += 2;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-grpc-tls-p12-password") && (i + 1 < argc)) {
            _snprintf_s(pConfig->grpc.szTlsServerP12Pass, _countof(pConfig->grpc.szTlsServerP12Pass), _TRUNCATE, "%S", argv[i + 1]);
            pConfig->fgRPC = TRUE;
            i += 2;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-grpc-port") && (i + 1 < argc)) {
            wcsncpy_s(pConfig->wszTcpPortGRPC, _countof(pConfig->wszTcpPortGRPC), argv[i + 1], _TRUNCATE);
            i += 2;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-grpc-listen-address") && (i + 1 < argc)) {
            _snprintf_s(pConfig->grpc.szListenAddress, _countof(pConfig->grpc.szListenAddress), _TRUNCATE, "%S", argv[i + 1]);
            i += 2;
            continue;
        }
        wprintf(L"Invalid argument '%s'\n", argv[i]);
        return FALSE;
    }
    if(pConfig->fUpdate && !pConfig->wszRemote[0]) {
        printf("Only possible to update remote service.");
        return FALSE;
    }
    if((pConfig->fInstall || pConfig->fUpdate) && (pConfig->fInsecure || pConfig->fInteractive)) {
        printf(
            "Installation of the service in insecure/no security mode is not allowed.\n" \
            "Service requires mutually authenticated kerberos(domain membership).    \n" \
            "No insecure / no security mode may only be enabled in interactive mode. \n");
        return FALSE;
    }
    if(!pConfig->fgRPC && !pConfig->fHTTP) {
        printf("No active transport protocol. gRPC and HTTP are disabled.\n");
        return FALSE;
    }
    if(pConfig->fgRPC && !pConfig->fInsecure && (!pConfig->grpc.szTlsClientCaCert[0] || !pConfig->grpc.szTlsServerP12[0] || !pConfig->grpc.szTlsServerP12Pass[0])) {
        printf("gRPC missing required parameters: -grpc-tls-p12, -grpc-tls-p12-password, -grpc-client-ca\n");
        return FALSE;
    }
    c += pConfig->fInstall ? 1 : 0;
    c += pConfig->fUpdate ? 1 : 0;
    c += pConfig->fUninstall ? 1 : 0;
    if(c > 1) {
        printf("Installation/Update/Uninstallation of agent may not take place simultaneously.\n");
        return FALSE;
    }
    return TRUE;
}

/*
* Main entry point of the service executable.
* -- argc
* -- argv
* -- return
*/
int wmain(int argc, wchar_t *argv[])
{
    LEECHSVC_CONFIG cfg = { 0 };
    DWORD cchLocalUserUPN = MAX_PATH;
    WCHAR wszLocalUserUPN[MAX_PATH] = { 0 };
    g_LeechAgent_IsService = FALSE;
    // PARSE ARGUMENTS AND VALIDITY CHECK
    if(!LeechSvc_ParseArgs(argc, argv, &cfg)) { return 0; }
	// CHILD PROCESS MODE
	if(cfg.fChildProcess) {
        LeechAgent_ProcChild_Main(argc, argv);
        return 1;
	}
    // TRY RUN SERVICE IN SERVICE MODE
    if(!(cfg.fInsecure || cfg.fInstall || cfg.fUpdate || cfg.fInteractive || cfg.fUninstall)) {
        SERVICE_TABLE_ENTRY DispatchTable[] = {
            { LEECHSVC_NAME, (LPSERVICE_MAIN_FUNCTION)LeechSvc_SvcMain },
            { NULL, NULL } };
        g_LeechAgent_IsService = TRUE;
        if(!StartServiceCtrlDispatcher(DispatchTable)) {
            LeechSvc_ReportEvent(L"StartServiceCtrlDispatcher");
            return 0;
        }
        return 0;
    }
    // UNINSTALL SERVICE
    if(cfg.fUninstall) {
        if(cfg.wszRemote[0]) {
            LeechSvc_DeleteRemoteRpc(cfg.wszRemote, FALSE, NULL);
        } else {
            LeechSvc_Delete(NULL, FALSE);
        }
        return 1;
    }
    // INSTALL SERVICE
    if(cfg.fInstall) {
        if(cfg.wszRemote[0]) {
            LeechSvc_InstallRemoteRpc(cfg.wszRemote);
        } else {
            LeechSvc_Install(cfg.wszRemote, NULL);
        }
        return 1;
    }
    // UPDATE SERVICE (UNINSTALL & INSTALL)
    if(cfg.fUpdate) {
        if(cfg.wszRemote[0]) {
            LeechSvc_DeleteRemoteRpc(cfg.wszRemote, FALSE, NULL);
            LeechSvc_InstallRemoteRpc(cfg.wszRemote);
        }
        return 1;
    }
    // RUN SERVICE IN INTERACTIVE MODE
    if(cfg.fInteractive) {
        if(cfg.fInsecure) {
            GetUserNameExW(NameUserPrincipal, wszLocalUserUPN, &cchLocalUserUPN);
            while(cchLocalUserUPN > 0) {
                cchLocalUserUPN--;
                if(wszLocalUserUPN[cchLocalUserUPN] == L'$') {
                    printf("Insecure mode not allowed when running in SYSTEM context in AD environment.\n");
                }
            }
        }
        LeechSvc_Interactive(&cfg);
        return 1;
    }
    // ERROR - SHOULD NOT HAPPEN ...
    return 1;
}
