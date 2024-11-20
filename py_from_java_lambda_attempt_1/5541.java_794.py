Here is the translation of the Java code to Python:
```
import tkinter as tk

class DisableFieldAction:
    def __init__(self, owner, panel):
        self.panel = panel
        super().__init__("Disable Field", owner, False)

    @property
    def help_location(self):
        return HelpLocation(HelpTopics.CODE_BROWSER, "Disable Field")

    def is_enabled_for_context(self, context):
        if isinstance(context.get_context_object(), FieldHeaderLocation):
            loc = context.get_context_object()
            ff = loc.get_field_factory()
            return ff and ff.is_enabled()

    def action_performed(self, context):
        factory = self.loc.get_field_factory()
        self.panel.set_tab_lock(True)
        factory.set_enabled(False)

class HelpLocation:
    def __init__(self, topic, description):
        self.topic = topic
        self.description = description

class FieldHeaderLocation:
    def get_field_factory(self):
        # implement this method to return the field factory object
        pass

class FieldFactory:
    def is_enabled(self):
        # implement this method to check if the field is enabled
        pass

# Example usage:
owner = "Ghidra"
panel = tk.Frame()  # replace with your panel object
action = DisableFieldAction(owner, panel)
```
Note that I had to make some assumptions about the Python equivalent of Java classes and methods. For example:

* In Java, `public class` is translated to a Python class definition.
* The `@Override` annotation in Java is not necessary in Python, as method overriding works differently.
* The `setPopupMenuData()` method in Java does not have an exact equivalent in Python (I assume it's related to creating a menu or popup window).
* I replaced the `ActionContext` and `DockingAction` classes with simple Python objects (`tkinter.Frame` for panel, etc.).
* I implemented some methods as placeholders, assuming that you will provide your own implementation.

Please let me know if this translation is correct or if there are any issues!