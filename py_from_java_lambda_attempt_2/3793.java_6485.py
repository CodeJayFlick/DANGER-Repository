Here is the translation of the Java code to Python:
```
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
```
Note that I used the `ghidra_app_plugin_core_disassembler` module as a placeholder for the Java package name. In Python, you would need to define this module or import it from elsewhere.

Also, keep in mind that Python is an interpreted language and does not have direct support for Java-like features such as classes with constructors (`__init__`) or method overriding (`@Override`). The above code uses Python's built-in syntax to achieve similar functionality.