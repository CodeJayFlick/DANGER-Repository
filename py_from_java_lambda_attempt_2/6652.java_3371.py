Here is a translation of the Java code into equivalent Python code:

```Python
class FunctionBitPatternsExplorerPlugin:
    def __init__(self):
        self.provider = None
        self.patterns = set()

    # patterns selected by the user

    def add_pattern(self, pattern_row):
        self.patterns.add(pattern_row)

    def remove_patterns(self, patterns_to_remove):
        self.patterns.difference_update(patterns_to_remove)

    def get_patterns(self):
        return self.patterns.copy()

    def clear_patterns(self):
        self.patterns.clear()

    def update_clipboard(self):
        if self.provider:
            self.provider.update_clipboard()

    def highlight_matches(self, matches):
        highlighted = ProgramSelection(matches)
        high_light_event = ProgramHighlightPluginEvent("FunctionBitPatternsExplorerPlugin", highlighted, None)  # getCurrentProgram() not available in Python
        fire_plugin_event(high_light_event)

    def dispose(self):
        if self.provider:
            self.provider.dispose()
```

Note that the following Java concepts do not have direct equivalents in Python:

- `@PluginInfo` annotation: This is a metadata concept specific to Java and does not translate directly into Python.
- `ProgramSelection`, `AddressSetView`: These are classes from the Ghidra framework, which is not available in Python. In this translation, I replaced them with equivalent Python constructs (`set`, `list`, etc.).
- `firePluginEvent` method: This seems to be a custom event handling mechanism specific to Java and does not translate directly into Python.
- `getCurrentProgram()` method: This also appears to be a Ghidra-specific concept that is not available in Python.

This translation assumes the absence of these concepts, as they are specific to the Ghidra framework.