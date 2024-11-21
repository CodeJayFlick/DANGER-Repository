Here is the translation of the given Java code into Python:

```Python
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class Movement:
    """Movement property."""
    
    WALKING = ("walking",)
    SWIMMING = ("swimming",)
    FLYING = ("flying",)

    def __init__(self, title):
        self.title = title
    
    def __str__(self):
        return self.title
```

Please note that Python does not have an exact equivalent of Java's enum. The above code uses a class with static variables to simulate the behavior of an enum in Java.