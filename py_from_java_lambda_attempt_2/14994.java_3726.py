Here is the translation of the given Java code into Python:

```Python
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class Color:
    """Color property."""
    
    DARK = ("dark",)
    LIGHT = ("light",)
    GREEN = ("green",)
    RED = ("red",)

    def __init__(self, title):
        self.title = title

    def __str__(self):
        return self.title
```

Please note that Python does not have an exact equivalent of Java's enum. The above code uses a class with static variables to achieve similar functionality.