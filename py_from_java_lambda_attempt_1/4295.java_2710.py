Here is the translation of the given Java code into Python:

```Python
class RestoreSelectionPlugin:
    RESTORE_SELECTION_ACTION_NAME = "Restore Selection"

    def __init__(self):
        self.program_to_selection_map = {}
        self.restore_selection_action = None

    def create_actions(self):
        action = DockingAction(RESTORE_SELECTION_ACTION_NAME, self.name)
        action.actionPerformed = lambda context: self.fire_plugin_event(
            ProgramSelectionPluginEvent(self.name, 
                                         self.get_program_selection_state().get_selection_to_restore(), 
                                         current_program))

        menu_data = MenuData([ToolConstants.MENU_SELECTION, RESTORE_SELECTION_ACTION_NAME], None, "SelectUtils")
        action.set_menu_bar_data(menu_data)
        action.set_help_location(HelpLocation(HelpTopics.SELECTION, RESTORE_SELECTION_ACTION_NAME))
        action.setEnabled(False)

        self.restore_selection_action = action
        tool.add_action(action)

    def dispose(self):
        self.program_to_selection_map.clear()
        super().dispose()

    def program_activated(self, program):
        if not self.get_program_selection_state(program):
            selection_state = SelectionState()
            self.program_to_selection_map[program] = selection_state

        self.restore_selection_action.setEnabled(selection_state.can_restore_selection())

    def program_closed(self, program):
        del self.program_to_selection_map[program]

    def selection_changed(self, selection):
        if not current_program:
            return
        selection_state = self.get_program_selection_state(current_program)
        if not selection_state:
            return

        selection_state.push_selection(selection)

        # make sure we eventually enable the action (once we've had a valid selection,
        # then the action will always be enabled for a given program, so no need to disable
        # the action here).
        self.restore_selection_action.setEnabled(True if selection_state.can_restore_selection() else False)


class SelectionState:
    def __init__(self):
        self.active_selection = ProgramSelection()
        self.previous_restore_selection = ProgramSelection()

    def get_selection_to_restore(self):
        if not self.previous_restore_selection or self.previous_restore_selection.is_empty():
            raise AssertException("Tried to restore a selection with no previous selection saved")

        return self.previous_restore_selection

    def push_selection(self, new_selection):
        # only store a selection for later use if it is valid (restorable) and it is not
        # the same as the incoming selection

        if not new_selection:
            new_selection = ProgramSelection()

        if self.active_selection == new_selection:
            return

        if not self.active_selection.is_empty():
            self.previous_restore_selection = self.active_selection

        self.active_selection = new_selection

    def can_restore_selection(self):
        if not self.previous_restore_selection or self.previous_restore_selection.is_empty():
            return False

        if self.previous_restore_selection == self.active_selection:
            return False

        return True
```

Please note that Python does not have direct equivalent of Java's `@PluginInfo` and other annotations.