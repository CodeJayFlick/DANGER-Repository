Here is the translation of the Java code into Python:

```Python
class RenameGlobalAction:
    def __init__(self):
        self.name = "Rename Global"
        self.help_location = HelpLocation(HelpTopics.DECOMPILER, "ActionRenameGlobal")
        self.popup_menu_data = MenuData(["Rename Global"], "Decompile")
        self.key_binding_data = KeyBindingData(KeyEvent.VK_L, 0)

    def is_enabled_for_decompiler_context(self, context):
        function = context.get_function()
        if not (function and isinstance(function, Function)):
            return False

        token_at_cursor = context.get_token_at_cursor()
        if not token_at_cursor:
            return False
        if isinstance(token_at_cursor, ClangFieldToken):
            return False

        high_symbol = self.find_high_symbol_from_token(token_at_cursor, context.get_high_function())
        if not (high_symbol and not isinstance(high_symbol, HighFunctionShellSymbol)):
            return False
        return high_symbol.is_global()

    def decompiler_action_performed(self, context):
        tool = context.get_tool()
        token_at_cursor = context.get_token_at_cursor()
        high_symbol = self.find_high_symbol_from_token(token_at_cursor, context.get_high_function())
        symbol = None

        if isinstance(high_symbol, HighCodeSymbol):
            code_symbol = (high_symbol).get_code_symbol()
            if not code_symbol:
                # Try to get the dynamic symbol
                addr = ((HighCodeSymbol) high_symbol).get_storage().get_min_address()
                symbol_table = context.get_program().get_symbol_table()
                symbol = symbol_table.get_primary_symbol(addr)
            else:
                symbol = code_symbol

        if not symbol:
            print("Rename Failed: Memory storage not found for global variable")
            return
        dialog = AddEditDialog("Rename Global", tool)
        dialog.edit_label(symbol, context.get_program())

    def find_high_symbol_from_token(self, token_at_cursor, high_function):
        # This method is missing in the original Java code. It seems to be searching 
        # for a HighSymbol from a given ClangToken and HighFunction.
        pass

class HelpLocation:
    def __init__(self, topic, help_text):
        self.topic = topic
        self.help_text = help_text

class MenuData:
    def __init__(self, menu_items, popup_name):
        self.menu_items = menu_items
        self.popup_name = popup_name

class KeyBindingData:
    def __init__(self, key_code, modifiers):
        self.key_code = key_code
        self.modifiers = modifiers

# These classes are missing in the original Java code. They seem to be custom classes.
```

Please note that this translation is not perfect as some parts of the original Java code (like `find_high_symbol_from_token` method) were left out, and also Python does not have direct equivalent for all Java constructs like static methods or interfaces.