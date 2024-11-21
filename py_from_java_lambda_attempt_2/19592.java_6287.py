Here is a direct translation of the Java code into equivalent Python:

```Python
# This file is part of Skript.
#
# Skript is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

class InventoryActionExpression:
    def __init__(self):
        pass

    @property
    def name(self):
        return "Inventory Action"

    @property
    def description(self):
        return "The inventory action of an inventory event. Please click on the link for more information."

    @property
    def examples(self):
        return ["inventory action is pickup all"]

    @property
    def since(self):
        return "2.2-dev16"

    def to_string(self, e=None, debug=False):
        if debug:
            return f"the inventory action ({e})"
        else:
            return "the inventory action"
```

Please note that Python does not have direct equivalents for Java's annotations (`@Name`, `@Description`, etc.) or static initialization blocks.