import ghidra_app_plugin_core_disassembler as disassembler

class RestrictedDisassembleAction:
    def __init__(self, plugin: disassembler.DisassemblerPlugin, group_name: str):
        self.plugin = plugin
        super().__init__("Disassemble (Restricted)", plugin.name)
        set_popup_menu_data(new MenuData(["Disassemble (Restricted)"], None, group_name))

    def actionPerformed(self, context: "ListingActionContext"):
        self.plugin.disassemble_restricted_callback(context)

    def is_enabled_for_context(self, context: "ListingActionContext") -> bool:
        return self.plugin.check_disassembly_enabled(context, context.address, True)
