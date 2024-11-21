Here is the translation of the Java code into Python:

```Python
class SetOperandLabelAction:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Set Operand Label", plugin.name)

        popup_menu_data = {"path": ["Set Associated Label..."], "label": "Label"}
        key_binding_data = {"key_stroke": ("l", True, True)}
        set_popup_menu_data(popup_menu_data)
        set_key_binding_data(key_binding_data)
        self.enabled = True

    def is_enabled_for_context(self, context):
        if not isinstance(context.location, OperandFieldLocation):
            return False
        return (not self.plugin.is_on_external_reference(context) and 
                not self.plugin.is_on_variable_reference(context) and 
                self.plugin.is_on_symbol(context))

    def action_performed(self, context):
        self.plugin.set_operand_label_callback(context)
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements or the `@Override` annotation. The equivalent of a Java class is simply defined using the `class` keyword in Python.

Also note that there are some differences between how you handle events and actions in Java versus Python. In this translation, I've used the same method names as before (`actionPerformed`) but it's not exactly the same thing.