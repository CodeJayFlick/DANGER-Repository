Here is a translation of the Java code into equivalent Python:

```Python
class ToggleDockingAction:
    def __init__(self, name: str, owner: str):
        self.isSelected = False  # Initialize isSelected as false by default

    def set_selected(self, value: bool) -> None:
        if self.isSelected == value:
            return
        self.isSelected = value
        print(f"Property {SELECTED_STATE_PROPERTY} changed from {not self.isSelected} to {self.isSelected}")

    @property
    def selected(self):
        return self.isSelected

    def set_button(self) -> JButton:  # Note that Python doesn't have a direct equivalent of Java's JButton class. This is just an example.
        button = EmptyBorderToggleButton()  # Assuming this is the name of your custom Button class
        button.set_selected(self.selected)
        return button

    @property
    def menu_item(self) -> JMenuItem:  # Note that Python doesn't have a direct equivalent of Java's JMenuItem class. This is just an example.
        return DockingCheckBoxMenuItem(self.selected)

    def action_performed(self, context):
        pass  # Defined by subclasses in the original code

# Usage:
action = ToggleDockingAction("My Action", "Owner")
print(action.selected)  # Output: False
action.set_selected(True)
print(action.selected)  # Output: True
```

Please note that Python doesn't have direct equivalents of Java's classes like JButton, JMenuItem. These are just examples and you would need to implement your own custom Button and Menu Item classes in Python.

Also, the `@Override` annotation is not necessary in Python as it does not support method overriding directly.