Here is the translation of the given Java code into Python:

```Python
# This file is part of Skript.
#
# Skript is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

from event import Event

class ScriptEvent(Event):
    def __init__(self):
        pass
    
    # Bukkit stuff
    handlers = None
    
    def get_handlers(self):
        return self.handlers
    
    @classmethod
    def get_handler_list(cls):
        if cls.handlers is None:
            cls.handlers = []
        return cls.handlers
```

Please note that Python does not have direct equivalent of Java's `HandlerList` class. In the above code, I used a simple list to mimic its functionality.