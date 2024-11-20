Here is the translation of the given Java code into Python:

```Python
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class Nourishment:
    """Nourishment enumeration."""
    
    SATURATED = ("saturated",)
    HUNGRY = ("hungry",)
    STARVING = ("starving",)

    def __init__(self, title):
        self.title = title

    def __str__(self):
        return self.title
```

Note that Python does not have an exact equivalent to Java's enum. The above code uses a class with static variables and methods to achieve similar functionality.