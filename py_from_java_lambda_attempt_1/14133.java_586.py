Here is the translation of the given Java code into Python:

```Python
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class ThreadCompleteListener:
    """Interface with listener behaviour related to Thread Completion."""
    
    def completed_event_handler(self, event_id: int):
        pass
```

Note that in Python, we don't have a direct equivalent of Java's `interface` keyword. Instead, we define a class and use the convention that classes intended for inheritance should start with an uppercase letter (like `ThreadCompleteListener`). The methods defined within this class are meant to be overridden by any subclass.

Also note that I've used type hints (`int`) in the method signature as per Python 3.x's syntax.