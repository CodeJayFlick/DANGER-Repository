class MipsDisassembleAction:
    def __init__(self, plugin, group_name, disassemble_mips16):
        self.plugin = plugin
        self.group_name = group_name
        self.disassemble_mips16 = disassemble_mips16

        super().__init__("Disassemble " + ("MIPS16/Micromips" if disassemble_mips16 else "MIPS"), plugin.name)

    def set_help_location(self, location):
        # Need to override the default help location since this action doesn't have its own
        # section in the help.
        self.help_location = location

    def set_popup_menu_data(self, menu_data):
        # menu data will be adjusted based upon specific popup context
        if self.disassemble_mips16:
            key_event = 123  # equivalent to KeyEvent.VK_F12
        else:
            key_event = 122  # equivalent to KeyEvent.VK_F11

        self.key_binding_data = {"key_event": key_event, "modifiers": []}

    def actionPerformed(self, context):
        self.plugin.disassemble_mips_callback(context, self.disassemble_mips16)

    def is_add_to_popup(self, context):
        if not self.is_enabled_for_context(context):
            return False

        # Prior to returning, we are resetting the menu action to match that of the language ID.
        # this could not be done up in the constructor since the program has not been set yet.

        lang_name = context.get_program().get_language().get_id()
        if "micro" in lang_name or "R6" in lang_name:
            alternate_mips = "MicroMips"
        else:
            alternate_mips = "MIPS16e"

        self.set_popup_menu_data({"menu_items": ["Disassemble - " + (self.disassemble_mips16 and alternate_mips or "MIPS")], "group_name": self.group_name})

        return True

    def is_enabled_for_context(self, context):
        address = context.get_address()
        if address is None:
            return False

        program = context.get_program()
        lang = program.get_language()
        proc = lang.get_processor()

        if not "MIPS" == str(proc):  # equivalent to "MIPS".equals(toString())
            return False

        register = context.get_program().get_register("ISA_MODE")
        if register is None:
            return False

        return self.plugin.check_disassembly_enabled(context, address, True)
