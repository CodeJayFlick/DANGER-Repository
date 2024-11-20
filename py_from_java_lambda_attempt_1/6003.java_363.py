Here is the translation of the given Java code into Python:

```Python
class SelectionNavigationAction:
    ACTION_NAME = "Selection Navigation Action"

    def __init__(self, plugin_name: str, table):
        super().__init__(plugin_name, table)

    @property
    def table(self) -> object:
        return self._table

    @table.setter
    def table(self, value):
        if isinstance(value, GhidraTable):
            self._table = value
        else:
            raise ValueError("The provided table must be an instance of GhidraTable")

class AbstractSelectionNavigationAction:
    def __init__(self, action_name: str, owner: str, table):
        pass

    def toggle_selection_listening(self, listen: bool) -> None:
        if self.table is not None and isinstance(self.table, GhidraTable):
            (GhidraTable).set_navigate_on_selection_enabled(listen)
        super().save_state()

class GhidraTable:
    @property
    def navigate_on_selection_enabled(self) -> bool:
        pass

    @navigate_on_selection_enabled.setter
    def set_navigate_on_selection_enabled(self, value: bool):
        pass
```

Please note that this is a direct translation of the Java code into Python. The original code has some dependencies and abstract classes which are not directly translatable to Python without additional information about those dependencies and how they should be implemented in Python.

Also, please note that I have assumed `GhidraTable` as an existing class in your Python program. If it's not the case, you would need to implement this class according to its functionality in Java.