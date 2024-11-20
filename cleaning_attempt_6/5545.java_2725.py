import tkinter as tk

class RemoveFieldAction:
    def __init__(self, owner, panel):
        self.panel = panel
        super().__init__("Remove Field", owner, False)

        menu_data = {"Remove Field": None}
        set_popup_menu(menu_data)
        enable(True)
        help_location = HelpLocation(HelpTopics.CODE_BROWSER, "Remove Field")
        set_help_location(help_location)

    def is_enabled_for_context(self, context):
        context_object = context.get_context_object()
        if isinstance(context_object, FieldHeaderLocation):
            self.loc = context_object
            return self.loc.get_field_factory() is not None
        return False

    def action_performed(self, context):
        panel.set_tab_lock(True)
        loc.get_model().remove_factory(loc.get_row(), loc.get_column())

class HelpTopics:
    CODE_BROWSER = "Code Browser"

class FieldHeaderLocation:
    pass

class FieldHeader:
    pass

class DockingAction:
    def __init__(self, name, owner, enabled):
        self.name = name
        self.owner = owner
        self.enabled = enabled

    def set_popup_menu(self, menu_data):
        # implement me!

    def enable(self, value):
        self.enabled = value

    def get_help_location(self):
        return None  # implement me!

class HelpLocation:
    pass

# usage example
panel = FieldHeader()
action = RemoveFieldAction("owner", panel)
