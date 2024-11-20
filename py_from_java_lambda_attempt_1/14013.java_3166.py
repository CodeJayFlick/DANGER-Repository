Here is the translation of the given Java code into Python:

```Python
# The MIT License
# Copyright © 2014-2021 Ilkka Seppälä

class Troll:
    """Interface for trolls."""

    def attack(self):
        pass

    def get_attack_power(self):
        pass

    def flee_battle(self):
        pass
```

Note that in Python, we don't have a direct equivalent of Java's `interface` keyword. Instead, we define classes with abstract methods using the `pass` statement to indicate that these methods are intended to be implemented by subclasses.