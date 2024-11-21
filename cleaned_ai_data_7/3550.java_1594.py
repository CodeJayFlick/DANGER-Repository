class ApplyAction:
    ACTION_NAME = "Apply Editor Changes"
    GROUP_NAME = "BASIC_ACTION_GROUP"
    ICON = None  # Assuming you will load this icon separately in your program
    POPUP_PATH = ["Apply Edits"]

    def __init__(self, provider):
        self.provider = provider

    def set_description(self):
        return "Apply editor changes"

    def adjust_enablement(self):
        has_changes = self.model.has_changes()
        valid_name = self.model.is_valid_name()
        self.enabled = has_changes and valid_name

class CompositeEditorTableAction:
    pass  # This class is not implemented in the given Java code, so it's left empty here.

# Assuming you have a model object with methods 'has_changes', 'is_valid_name' and 'apply'
model = None
action = ApplyAction(model)
