Here is a translation of the Java code into equivalent Python:

```Python
class HotbarButton:
    def __init__(self):
        self.name = "Hotbar Button"
        self.description = ("The hotbar button clicked in an inventory click event.")
        self.examples = ["on inventory click:", "  send \"You clicked the hotbar button %hotbar button%!\""]
        self.since = "2.5"

    def init(self, exprs, matched_pattern, is_delayed, parser):
        if not isinstance(parser.current_event(), InventoryClickEvent):
            print("The 'hotbar button' expression may only be used in an inventory click event.")
            return False
        return True

    def get(self, e):
        if isinstance(e, InventoryClickEvent):
            return [(e.get_hotbar_button())]
        return None

    @property
    def is_single(self):
        return True

    @property
    def return_type(self):
        from typing import Union
        return Union[int]

    def __str__(self, e=None, debug=False):
        if not isinstance(e, InventoryClickEvent) and not debug:
            return "the hotbar button"
```

Note that Python does not have direct equivalents for Java's annotations (`@Name`, `@Description`, etc.) or static initialization blocks. I've replaced these with simple attribute assignments in the constructor.

Also note that this code assumes you have a separate class definition for an `InventoryClickEvent` object, which is not provided here.