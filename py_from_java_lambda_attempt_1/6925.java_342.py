Here is a translation of the Java code into equivalent Python:

```Python
class RemoveLabelAction:
    POPUP_PATH = ["Remove Label"]
    KEYBINDING = "Delete"

    def __init__(self):
        super().__init__("Remove Label", "Shared")
        
        self.set_help_location(HelpLocation("Decompile", "ActionRemoveLabel"))
        
        # same keybinding as the other remove actions
        self.set_popup_menu_data(MenuData(self.POPUP_PATH, "Decompile"))
        self.set_key_binding_data(KeyBindingData(self.KEYBINDING))

    def is_enabled_for_decompiler_context(self, context):
        token_at_cursor = context.get_token_at_cursor()
        
        if not isinstance(token_at_cursor, ClangLabelToken):
            return False
        
        symbol = self.get_symbol(context)
        return self.can_remove_symbol(symbol)

    def can_remove_symbol(self, s):
        return s is not None and s.source != SourceType.DEFAULT and not s.is_external

    def decompiler_action_performed(self, context):
        symbol = self.get_symbol(context)
        
        cmd = DeleteLabelCmd(symbol.address, symbol.name, symbol.parent_namespace)
        tool = context.get_tool()
        
        if not tool.execute(cmd, context.program):
            tool.set_status_info(cmd.status_msg)

class MenuData:
    def __init__(self, path, label):
        self.path = path
        self.label = label

class KeyBindingData:
    def __init__(self, keybinding):
        self.keybinding = keybinding

# Note: This is a simplified translation and may not work exactly as the original Java code.
```

Please note that this Python code does not have direct equivalent of some classes like `DecompilerActionContext`, `ClangLabelToken`, etc. These are custom classes in Java which might be used for specific purposes, but they do not exist in standard Python libraries or modules.