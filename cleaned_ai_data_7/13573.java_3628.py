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
