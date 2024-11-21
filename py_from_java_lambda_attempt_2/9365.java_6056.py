Here is the translation of the given Java code into equivalent Python:

```Python
class DropCode:
    INVALID = 0
    STACK = 1
    LEFT = 2
    RIGHT = 3
    TOP = 4
    BOTTOM = 5
    ROOT = 6
    WINDOW = 7

    def get_cursor(self):
        cursor_map = {
            self.LEFT: "left",
            self.RIGHT: "right",
            self.TOP: "top",
            self.BOTTOM: "bottom",
            self.STACK: "stack",
            self.ROOT: "stack",
            self.WINDOW: "new_window"
        }
        return cursor_map.get(self, "no_drop")

    def get_window_position(self):
        position_map = {
            self.LEFT: "left",
            self.RIGHT: "right",
            self.TOP: "top",
            self.BOTTOM: "bottom",
            self.STACK: "stack",
            self.INVALID: "stack"
        }
        return position_map.get(self, "stack")
```

This Python code defines an enum-like class `DropCode` with the same values as in Java. The methods `get_cursor()` and `get_window_position()` are implemented to mimic their Java counterparts.