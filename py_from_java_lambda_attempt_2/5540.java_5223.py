Here is the translation of the Java code to Python:
```python
import tkinter as tk

class AddSpacerFieldAction:
    def __init__(self, owner, panel):
        self.panel = panel
        super().__init__("Add Spacer Field", owner, False)
        self.set_popup_menu_data(["Add Field", "Spacer"], "header a")
        self.set_enabled(True)

    @property
    def help_location(self):
        return HelpLocation(HelpTopics.CODE_BROWSER, "Add Field")

    def is_enabled_for_context(self, context):
        return isinstance(context.get_context_object(), FieldHeaderLocation)

    def action_performed(self, context):
        location = context.get_context_object()
        model_at_location = location.get_model()
        self.panel.set_tab_lock(True)
        model_at_location.add_factory(SpacerFieldFactory(), location.get_row(), location.get_column())

class SpacerFieldFactory:
    pass

class FieldHeaderLocation:
    def __init__(self, row, column):
        self.row = row
        self.column = column

    @property
    def get_model(self):
        return None  # Replace with actual implementation

    @property
    def get_row(self):
        return self.row

    @property
    def get_column(self):
        return self.column

class HelpLocation:
    def __init__(self, topic, location):
        self.topic = topic
        self.location = location

# Example usage:
owner = "Ghidra"
panel = FieldHeader(panel)
action = AddSpacerFieldAction(owner, panel)
```
Note that I had to make some assumptions about the Python equivalent of Java classes and methods. For example:

* `DockingAction` is not a standard Python class, so I replaced it with a simple Python class.
* `MenuData` is also not a standard Python class, so I removed it altogether (since menu data can be handled using Tkinter's built-in menu functionality).
* `FieldHeaderLocation`, `SpacerFieldFactory`, and other classes were translated to their equivalent Python classes.

Please note that this translation may require further modifications to work correctly in your specific use case.