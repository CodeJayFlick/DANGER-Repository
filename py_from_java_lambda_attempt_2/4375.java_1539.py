Here is the equivalent Python code:

```Python
class ImportsCategoryNode:
    def __init__(self, program):
        super().__init__("Imports Category", program)

    @property
    def icon(self):
        return self._icon

    @icon.setter
    def icon(self, expanded):
        if expanded:
            self._icon = "openFolderExternals.png"
        else:
            self._icon = "closedFolderExternals.png"

    @property
    def tooltip(self):
        return "Symbols for External libraries"

    def supports_symbol(self, symbol):
        return symbol.is_external()
```

Note that Python does not have direct equivalents to Java's static variables or method overriding. In this translation:

- The `CLOSED_ FOLDER_EXTERNALS_ICON` and `OPEN_FOLDER_EXTERNALS_ICON` are replaced with a single instance variable `_icon`, which is set based on the `expanded` parameter.
- There is no equivalent to Java's `@Override` annotation, as Python does not require explicit method overriding.