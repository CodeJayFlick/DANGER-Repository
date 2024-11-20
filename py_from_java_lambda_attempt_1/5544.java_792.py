Here is the translation of the Java code to Python:
```python
import tkinter as tk
from tkinter import messagebox

class RemoveAllFieldsAction:
    def __init__(self, owner, panel):
        self.panel = panel
        super().__init__("Remove All Fields", owner, False)

        menu_data = {"Remove All Fields": "field"}
        self.set_menu_data(menu_data)
        self.set_enabled(True)
        help_location = HelpLocation(HelpTopics.CODE_BROWSER, "Remove Field")
        self.set_help_location(help_location)

    def is_enabled_for_context(self, context):
        return isinstance(context.get_context_object(), FieldHeaderLocation)

    def action_performed(self, context):
        user_choice = OptionDialog.show_option_dialog(
            panel,
            "Remove All Fields?",
            f"There is no undo for this action.\n" + 
            "Are you sure you want to remove all fields? ",
            "Continue",
            OptionDialog.WARNING_MESSAGE
        )
        if user_choice == OptionDialog.CANCEL_OPTION:
            return

        self.panel.set_tab_lock(True)

        loc = context.get_context_object()
        model_at_location = loc.get_model()
        model_at_location.remove_all_factories()

class FieldHeaderLocation:
    def __init__(self, model):
        self.model = model

class HelpTopics:
    CODE_BROWSER = "Code Browser"

class OptionDialog:
    WARNING_MESSAGE = 0
    CANCEL_OPTION = -1

    @staticmethod
    def show_option_dialog(owner, title, message, option_text, default=None):
        # This is a simplified implementation of the Java code.
        # In Python, we don't have built-in support for modal dialogs like in Java,
        # so this will just simulate it by showing an alert box and returning the user's choice.
        result = messagebox.askyesno(title, message)
        if default == "cancel":
            return -1
        elif default == "continue":
            return 0
        else:
            return int(result)

class HelpLocation:
    def __init__(self, topic, help_text):
        self.topic = topic
        self.help_text = help_text

# Example usage:
panel = FieldHeader(panel)
action = RemoveAllFieldsAction("owner", panel)
```
Note that I had to make some simplifications and assumptions about the Java code, as Python has different built-in support for certain features (e.g., modal dialogs). Additionally, I did not include any imports or dependencies specific to the original Java code.