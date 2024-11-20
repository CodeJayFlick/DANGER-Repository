Here is the translation of the Java code to Python:
```python
import ghidra_app_plugin_core_symboltree_actions as symbol_tree_action_context
from ghidra_framework_plugintool import Plugin
from ghidra_program_model_address import AddressSet
from ghidra_program_model_listing_codeunit import CodeUnit
from ghidra_program_model_listing_variable import Variable

class SelectionAction:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Make Selection", plugin.name)
        set_popup_menu_data(["Make Selection"], "0Middle")

    @property
    def is_enabled_for_context(self, context: symbol_tree_action_context.SymbolTreeContext) -> bool:
        for s in context.symbols:
            if not s.is_external():
                return True
        return False

    def action_performed(self, context: symbol_tree_action_context.SymbolTreeContext):
        address_set = AddressSet()
        for symbol in context.symbols:
            if symbol.is_external():
                continue
            symbol_object = symbol.object
            if isinstance(symbol_object, namespace.Namespace):
                namespace = symbol_object
                address_set.add(namespace.body)
            elif isinstance(symbol_object, variable.Variable):
                program_location = symbol.program_location
                address_set.add_range(program_location.address, program_location.address)
            elif isinstance(symbol_object, codeunit.CodeUnit):
                cu = symbol_object
                address_set.add_range(cu.min_address, cu.max_address)

        if not address_set.is_empty():
            self.plugin.fire_plugin_event(
                ProgramSelectionPluginEvent(self.plugin.name,
                    ProgramSelection(address_set), context.program))

if __name__ == "__main__":
    plugin = Plugin()
    selection_action = SelectionAction(plugin)
```
Note that I had to make some assumptions about the Python equivalent of Java classes and methods, as well as the structure of the `Ghidra` framework. This code may not be exact or complete, but it should give you a good starting point for translating the original Java code to Python.