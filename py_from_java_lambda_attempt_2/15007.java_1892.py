Here is the translation of the Java code to Python:
```
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class SizeSelector:
    def __init__(self, size: 'Size') -> None:
        self.size = size

    def test(self, creature: object) -> bool:
        return getattr(creature, 'getSize', lambda: None())() == self.size
```
Note that I've used type hints for the `size` parameter and the `test` method, as well as for the `creature` argument in the `test` method. This is not strictly necessary, but it can help with code readability and maintainability.

Also, I've assumed that there are classes or functions named `Size`, `Creature`, and `AbstractSelector` available elsewhere in your Python program. If these do not exist, you will need to define them before using this class.

Finally, the translation of Java's `equals()` method is a bit tricky because Python does not have an exact equivalent. In this case, I've used the `==` operator to compare the size values directly.