#include <windows.h>
#include <winreg.h>
#include <cstdio>
#include <cstring>

static void TrimNewline(char* s) {
    size_t n = strlen(s);
    while(n && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[--n] = '\0';
    }
}

int main() {
    char host[128] = { 0 };
    char port[16] = { 0 };
    char remote[256] = { 0 };
    char choice[16] = { 0 };
    const char* valueName = "Remote_rpc";

    printf("Select registry value to write:\n");
    printf("1) Remote_rpc (TCP target, recommended)\n");
    printf("2) Remote (legacy/default)\n> ");
    if(fgets(choice, sizeof(choice), stdin)) {
        TrimNewline(choice);
    }
    if(choice[0] == '2') {
        valueName = "Remote";
    }

    printf("Enter target IP or full HTTP/TCP URL:\n> ");
    if(!fgets(host, sizeof(host), stdin)) return 1;
    TrimNewline(host);
    if(strlen(host) == 0) {
        printf("No input. Exit.\n");
        return 1;
    }

    if(strncmp(host, "http://", 7) == 0) {
        strncpy_s(remote, host, _TRUNCATE);
    } else {
        if(strstr(host, "://")) {
            printf("Only http:// URL is supported in this RegSetter.\n");
            return 1;
        }
        printf("Port (default 4000, press Enter to use default):\n> ");
        if(fgets(port, sizeof(port), stdin)) {
            TrimNewline(port);
        }
        if(strlen(port) == 0) {
            strcpy_s(port, "4000");
        }
        _snprintf_s(remote, _TRUNCATE, "http://%s:%s,pool=32", host, port);
    }

    HKEY hKey;
    LSTATUS st = RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\RiverClient", 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    if(st != ERROR_SUCCESS) {
        printf("RegCreateKeyEx failed: %ld\n", st);
        return 2;
    }

    st = RegSetValueExA(hKey, valueName, 0, REG_SZ, reinterpret_cast<const BYTE*>(remote), (DWORD)strlen(remote) + 1);
    RegCloseKey(hKey);
    if(st != ERROR_SUCCESS) {
        printf("RegSetValueEx failed: %ld\n", st);
        return 3;
    }

    printf("Saved %s = %s\nPress Enter to exit...", valueName, remote);
    getchar();
    return 0;
}
