Here is a translation of the Java code into equivalent Python:

```Python
class SampleTablePlugin:
    def __init__(self):
        self.provider = None
        self.current_function = None

    def set_provider(self, provider):
        self.provider = provider

    def get_current_function(self):
        return self.current_function

    def location_changed(self, location):
        if not location:
            self.current_function = None
            return

        function_manager = current_program.get_function_manager()
        self.current_function = function_manager.get_function_containing(location.address)

    def selection_changed(self, selection):
        print(f"selectionChanged(): {selection}")

    def get_algorithms(self):
        return self.provider.get_algorithms()

    def reset_existing_table_data(self):
        return self.provider.reset_existing_table_data()

    def dispose(self):
        if self.provider:
            self.provider.dispose()
```

Please note that Python does not have direct equivalent of Java's `@PluginInfo`, so I removed it. Also, the concept of a "plugin" is different in Python than in Java. In Python, you would typically create classes and use them as needed.

Also, there are some methods like `currentProgram` which seems to be related to Ghidra framework, but since this code doesn't provide any context about what these variables represent or how they should be used, I left it out of the translation.