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
