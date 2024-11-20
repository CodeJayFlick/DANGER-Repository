Here is the translation of the Java code into Python:

```Python
class StaticDisassembleAction:
    def __init__(self, plugin, group_name):
        self.plugin = plugin
        super().__init__("Disassemble Static", plugin.name)

    @property
    def popup_menu_data(self):
        return {"menu_items": ["Disassemble (Static)"], "group_name": group_name}

    def run(self, context):
        self.plugin.disassemble_static_callback(context)


class DisassemblerPlugin:
    pass


# Usage example:

plugin = DisassemblerPlugin()
action = StaticDisassembleAction(plugin, "My Group")
```

Please note that Python does not have direct equivalent of Java's `package`, `import` statements. Also, the concept of a class having its own namespace is different in Python than it is in Java.

In this translation:

- The package structure has been removed.
- The import statement for `ListingActionContext` and `MenuData` classes are not present as they do not have direct equivalent in Python.
- A new class `DisassemblerPlugin` was added to match the naming convention of the original code.