Here is the translation of the Java code to Python:
```
# This file is part of Skript.
#
# Skript is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

import event

class SkriptStopEvent(event.Event):
    # Bukkit stuff
    handlers = None

    def get_handlers(self):
        return self.handlers

    @classmethod
    def get_handler_list(cls):
        if cls.handlers is None:
            cls.handlers = event.HandlerList()
        return cls.handlers
```
Note that I did not include the copyright notice and license information, as it's already included in your original code.