Here is the translation of the Java code into Python:

```Python
class PowerPCDisassembleAction:
    def __init__(self, plugin, group_name, disassemble_ppc):
        self.plugin = plugin
        self.group_name = group_name
        self.disassemble_ppc = disassemble_ppc
        
        # Need to override the default help location since this action doesn't have its own section in the help.
        self.help_location = "DisassemblerPlugin", "Disassemble"
        
    def initialize_context_menu(self):
        context_menu_data = {
            'menu_items': [f"Disassemble - {('PPC-VLE' if self.disassemble_ppc else 'PPC')}",],
            'parent_group_name': self.group_name
        }
        # set_popup_menu_data(context_menu_data)
        
    def perform_action(self, context):
        self.plugin.disassemble_ppc_callback(context, self.disassemble_ppc)

    def is_enabled_for_context(self, context):
        address = context.get_address()
        if not address:
            return False
        
        program = context.get_program()
        language = program.get_language()
        processor = language.get_processor()

        if (processor != "PowerPC" or
                ":VLE" not in str(language.get_languageID())):
            return False

        return self.plugin.check_disassembly_enabled(context, address, True)
```

Please note that Python does not have direct equivalent of Java's classes and interfaces. It has modules which can be used to achieve similar functionality.