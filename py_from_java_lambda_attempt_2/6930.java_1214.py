Here is the translation of the given Java code into equivalent Python:

```Python
class RenameLabelAction:
    def __init__(self):
        super().__init__("Rename Label")
        
        self.set_help_location(HelpLocation("DECOMPILER", "ActionRenameLabel"))
        
        # same keybinding as the other rename actions
        self.set_key_binding_data(KeyBindingData(KeyEvent.VK_L, 0))
        self.set_popup_menu_data(MenuData(["Rename Label"], "Decompile"))

    def is_enabled_for_decompiler_context(self, context):
        token_at_cursor = context.get_token_at_cursor()
        return isinstance(token_at_cursor, ClangLabelToken)

    def decompiler_action_performed(self, context):
        program = context.get_program()
        symbol_table = program.get_symbol_table()
        address = context.get_address()
        symbol = symbol_table.get_primary_symbol(address)
        
        dialog = AddEditDialog("", context.get_tool())
        dialog.edit_label(symbol, program)


class ClangLabelToken:
    pass

class DecompilerActionContext:
    def get_token_at_cursor(self):
        # Implement this method
        pass

    def get_program(self):
        # Implement this method
        pass

    def get_address(self):
        # Implement this method
        pass

    def get_tool(self):
        # Implement this method
        pass


class KeyBindingData:
    def __init__(self, key_event_code, modifiers):
        self.key_event_code = key_event_code
        self.modifiers = modifiers


class MenuData:
    def __init__(self, menu_items, popup_name):
        self.menu_items = menu_items
        self.popup_name = popup_name


class HelpLocation:
    def __init__(self, topic, help_topic):
        self.topic = topic
        self.help_topic = help_topic


class AddEditDialog:
    def edit_label(self, symbol, program):
        # Implement this method
        pass

```

Please note that the above Python code is not a direct translation of Java to Python. It's more like an equivalent implementation in Python. The original Java code might have some dependencies or imports which are missing here as they were removed for simplicity and readability purposes.