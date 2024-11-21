Here is a translation of the Java code into equivalent Python:

```Python
class DisassembleAction:
    def __init__(self, plugin, group_name):
        self.plugin = plugin
        
    def set_popup_menu_data(self, menu_data):
        pass  # Not implemented in this example
    
    def set_key_binding_data(self, keybinding_data):
        pass  # Not implemented in this example

    def perform_action(self, context):
        self.plugin.disassemble_callback(context)

    def is_enabled_for_context(self, context):
        address = context.get_address()
        if address is None:
            return False
        return self.plugin.check_disassembly_enabled(context, address, True)
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements or the `@Override` annotation. The equivalent of these in Python would be using modules and classes as needed.

Also note that this is a simplified translation without implementing all methods (like setting popup menu data) since it was not provided in the original code.