Here is the equivalent Python code:

```Python
class LinkGhidraCommand:
    def execute(self):
        window = get_active_workbench_window()
        selection = window.get_selection_service().get_selection()
        dialog = WizardDialog(window.get_shell(), LinkGhidraWizard(selection))
        dialog.open()

def get_active_workbench_window():
    # Implement this function to return the active workbench window
    pass

class LinkGhidraWizard:
    def __init__(self, selection):
        self.selection = selection

# You can use these classes as is or modify them according to your needs.
```

Please note that Python does not have direct equivalent of Java's Eclipse framework. So I had to remove the parts related to those frameworks and left some functions undefined (like `get_active_workbench_window`).