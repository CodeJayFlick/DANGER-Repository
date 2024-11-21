Here is the translation of the Java code to Python:

```Python
class ProgramLocationActionContext:
    def __init__(self, provider, program, location, selection=None, highlight=None):
        self.location = location
        self.selection = selection if selection else []
        self.highlight = highlight if highlight else []

    @property
    def location(self):
        return self._location

    @location.setter
    def location(self, value):
        self._location = value

    @property
    def selection(self):
        return self._selection

    @selection.setter
    def selection(self, value):
        if not isinstance(value, list):
            raise ValueError("Selection must be a list")
        self._selection = value

    @property
    def highlight(self):
        return self._highlight

    @highlight.setter
    def highlight(self, value):
        if not isinstance(value, list):
            raise ValueError("Highlight must be a list")
        self._highlight = value

    def get_address(self):
        if self.location:
            return self.location.get_address()
        else:
            return None

    def get_code_unit(self):
        if not hasattr(self, '_code_unit') or not self._code_unit:
            addr = self.get_address()
            if addr:
                cu = program.get_listing().get_code_unit_containing(addr)
                if isinstance(cu, Data) and self.location.component_path:
                    data = cu
                    cu = data.get_component(self.location.component_path)
        return getattr(self, '_code_unit', None)

    def has_selection(self):
        return bool(self.selection)

    def has_highlight(self):
        return bool(self.highlight)


class ProgramLocation:
    def __init__(self, address=None, component_path=None):
        self._address = address
        self._component_path = component_path

    @property
    def get_address(self):
        return self._address


class CodeUnit:
    pass  # This is a placeholder for the Python equivalent of Java's Data class


class ProgramSelection(list):  # Inherit from list to make it immutable by default
    pass
```

Please note that this translation does not include all possible error handling and edge cases. It also assumes that `program`, `provider` are already defined in your code, as well as the classes `Data` (equivalent of Java's Data class) and `Program`.