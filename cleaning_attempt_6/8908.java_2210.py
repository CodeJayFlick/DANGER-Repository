import tkinter as tk
from tkinter import messagebox

class RemoveMatchAction:
    MENU_GROUP = "UNEDIT_MENU_GROUP"
    ICON = None  # You need to load the icon image in Python

    def __init__(self, controller):
        self.controller = controller
        super().__init__("Remove", VTPlugin.OWNER)
        self.set_popup_menu_data(["Remove Match"], ICON, MENU_GROUP)
        self.setEnabled(False)
        self.help_location = "VersionTrackingPlugin/Remove_Match"

    def actionPerformed(self, context):
        match_context = context  # You need to implement this in Python
        matches = []  # Implement getSelectedMatches() method here
        session = self.controller.session  # Implement getSession() method here
        task = RemoveMatchTask(session, matches)  # Implement RemoveMatchTask class here
        self.controller.run_vt_task(task)
        self.controller.refresh()

    def is_enabled_for_context(self, context):
        if not isinstance(context, VTMatchContext):  # You need to implement this in Python
            return False

        match_context = context
        matches = []  # Implement getSelectedMatches() method here
        if len(matches) == 0:
            return False

        if not self.is_removable_match(matches[0]):
            return False  # It must be a single manual match.
        return True

    def is_removable_match(self, vt_match):
        return vt_match.match_set.has_removable_matches()  # You need to implement this in Python

    def is_add_to_popup(self, context):
        return True
