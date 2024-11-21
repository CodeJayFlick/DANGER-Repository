import tkinter as tk

class DiffIgnoreAllAction:
    ACTION_NAME = "Set Ignore for All Apply Settings"
    GROUP_NAME = "DIFF_APPLY_ACTION"
    DESCRIPTION = "Change all the difference type apply settings to Ignore."

    def __init__(self, provider):
        self.provider = provider
        super().__init__("Set All To Ignore", provider.get_plugin().get_name())
        self.set_menu_bar_data(self.menu_path(), self.GROUP_NAME)
        self.set_popup_menu_data(self.popup_path(), self.GROUP_NAME)

        self.description = DESCRIPTION

    def menu_path(self):
        return [self.ACTION_NAME]

    def popup_path(self):
        return [self.ACTION_NAME]

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, value):
        self._description = value

    def actionPerformed(self, context):
        self.provider.set_apply_filter(ProgramMergeFilter.ALL, ProgramMergeFilter.IGNORE)

class DockingAction:
    pass

class MenuData:
    def __init__(self, path, group_name):
        self.path = path
        self.group_name = group_name

class ActionContext:
    pass

class DiffApplySettingsProvider:
    @property
    def plugin(self):
        return None  # Replace with actual implementation

    def get_plugin(self):
        return self.plugin

    def set_apply_filter(self, filter_type, apply_settings):
        raise NotImplementedError("Not implemented")

# Example usage:
provider = DiffApplySettingsProvider()
action = DiffIgnoreAllAction(provider)
