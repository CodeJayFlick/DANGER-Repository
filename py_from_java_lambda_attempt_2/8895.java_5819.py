Here is the translation of the Java code to Python:
```
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
```
Note that I had to create a separate `VTMarkupItemApplyActionType` class in Python, as there is no direct equivalent of Java's enum type. In this implementation, the values are simply strings.

Also, I used property decorators (`@property`) to implement getter and setter methods for the `display_string` and `action` attributes, which is a common pattern in Python.