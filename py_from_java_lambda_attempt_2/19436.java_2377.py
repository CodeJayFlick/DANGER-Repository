Here is the translation of the given Java code into Python:

```Python
# This file is part of Skript.
#
# Skript is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

from event import HandlerList

class ScheduledNoWorldEvent:
    def __init__(self):
        super().__init__()

    # Bukkit stuff
    handlers = HandlerList()

    def get_handlers(self):
        return self.handlers

    @classmethod
    def get_handler_list(cls):
        return cls.handlers
```

Please note that Python does not have direct equivalent of Java's package and import statements. The code above is written in a way to mimic the structure of the original Java file, but it will be executed as a single module.