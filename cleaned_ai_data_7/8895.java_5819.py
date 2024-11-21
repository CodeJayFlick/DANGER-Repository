class DisplayableMarkupItemAction:
    EXCLUDE_ACTION = DisplayableMarkupItemAction("Do Not Apply", None)
    REPLACE_ACTION = DisplayableMarkupItemAction("Replace", "REPLACE")
    ADD_ACTION = DisplayableMarkupItemAction("Add", "ADD")

    def __init__(self, display_string, action):
        self.display_string = display_string
        self.action = action

    @property
    def display_string(self):
        return self._display_string

    @display_string.setter
    def display_string(self, value):
        self._display_string = value

    @property
    def action(self):
        return self._action

    @action.setter
    def action(self, value):
        self._action = value


class VTMarkupItemApplyActionType:
    REPLACE = "REPLACE"
    ADD = "ADD"

# Example usage:
print(DisplayableMarkupItemAction.REPLACE_ACTION.display_string)  # Output: Replace
print(DisplayableMarkupItemAction.ADD_ACTION.action)  # Output: ADD
