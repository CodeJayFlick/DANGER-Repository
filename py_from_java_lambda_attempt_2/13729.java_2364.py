Here is the translation of the given Java code into equivalent Python:

```Python
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class FishingBoatAdapter:
    """ Adapter class. Adapts the interface of the device (FishingBoat)
        into RowingBoat interface expected by the client (Captain). """

    def __init__(self):
        self.boat = FishingBoat()

    def row(self):
        self.boat.sail()
```

Please note that Python does not have direct equivalent to Java's `package` and `public class`. In Python, we define classes using the `class` keyword. Also, there is no need for explicit constructor (`__init__`) in Python as it gets called automatically when an object of a class is created.