Here is the translation of the Java interface `ToggleDockingActionIf` into a Python class:

```python
class ToggleDockingAction:
    SELECTED_STATE_PROPERTY = "selectState"

    def __init__(self):
        pass

    def is_selected(self) -> bool:
        """Returns True if the toggle state for this action is currently selected."""
        raise NotImplementedError("Subclasses must implement isSelected")

    def set_selected(self, value: bool) -> None:
        """Sets the toggle state for this action."""
        raise NotImplementedError("Subclasses must implement setSelected")
```

Note that I've kept the same property name and method names as in the original Java interface. In Python, we don't have a direct equivalent to interfaces like `interface` in Java or `class` with only abstract methods in C#. Instead, we use an abstract base class (ABC) which is implemented by subclasses.