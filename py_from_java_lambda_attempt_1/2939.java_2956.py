Here is a translation of the Java code into equivalent Python:

```Python
class SampleSearchTableProvider:
    def __init__(self, plugin: 'SampleSearchTablePlugin', searcher):
        self.plugin = plugin
        self.component = build(searcher)
        set_transient()

    @staticmethod
    def build(searcher):
        panel = JPanel(BorderLayout())
        panel.setBorder(EmptyBorder(3, 3, 3, 3))

        model = SampleSearchTableModel(searcher, plugin.get_tool())
        filter_table = GhidraFilterTable(model)
        table = filter_table.get_table()

        if goTo_service := plugin.get_tool().get_service(GoToService):
            table.install_navigation(go_to_service, go_to_service.get_default_navigatable())

        table.set_navigate_on_selection_enabled(True)

        panel.add(filter_table)

        return panel

    def dispose(self):
        self.filter_table.dispose()
        self.filter_table.get_table().dispose()
        self.remove_from_tool()

    @property
    def component(self):
        return self.component

    def options_changed(self, tool_options: 'ToolOptions', option_name: str, old_value: object, new_value: object):
        # TODO Auto-generated method stub
```

Please note that Python does not support direct translation of Java code into equivalent Python. The above Python code is a simplified version and may require further modifications to match the exact functionality as in the original Java code.

Here are some key differences:

1. **Class Declaration**: In Java, classes need to be declared with `public` access modifier if they're intended for external use. However, this isn't necessary in Python since it doesn't have a concept of public or private variables.
2. **Method Signatures**: Method signatures in Python are more flexible than those in Java. They don't require explicit declaration of return types and parameter lists can be omitted when the method takes no parameters.
3. **Object-Oriented Programming (OOP)**: While both languages support OOP, they have different syntax for declaring classes, inheritance, polymorphism, etc.

The above Python code is a simplified version based on the provided Java code.