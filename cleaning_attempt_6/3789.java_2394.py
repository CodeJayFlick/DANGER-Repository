class Hcs12DisassembleAction:
    def __init__(self, plugin, group_name, disassemble_xgate):
        self.plugin = plugin
        self.disassemble_xgate = disassemble_xgate
        
        # Need to override the default help location since this action doesn't have its own section in the help.
        self.help_location = HelpLocation("DisassemblerPlugin", "Disassemble")
        
        menu_data = MenuData([f"Disassemble - {group_name}"], None, group_name)
        key_binding_data = KeyBindingData(0 if disassemble_xgate else 1, 0) 
        self.set_help_location(self.help_location)
        self.set_popup_menu_data(menu_data)
        self.set_key_binding_data(key_binding_data)

    def action_performed(self, context):
        self.plugin.disassemble_hcs12_callback(context, self.disassemble_xgate)

    def is_enabled_for_context(self, context):
        address = context.get_address()
        if not isinstance(address, Address) or address is None:
            return False
        
        program = context.get_program()
        language = program.get_language()
        processor = language.get_processor()

        if str(processor) != "HCS12":
            return False

        register = context.get_program().get_program_context().get_register("XGATE")
        if not isinstance(register, Register):
            return False
        
        return self.plugin.check_disassembly_enabled(context, address, True)
