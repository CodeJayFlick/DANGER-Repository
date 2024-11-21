Here is the translation of the Java code to Python:
```
class NestedDelaySlotException(Exception):
    def __init__(self):
        super().__init__("Nested delay slotted instruction not permitted")
```
Note that I've used the built-in `Exception` class in Python as a base class, and defined a new subclass called `NestedDelaySlotException`. The constructor (`__init__`) takes no arguments and calls the parent's constructor with a message.