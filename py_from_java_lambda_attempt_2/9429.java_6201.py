Here is the translation of the given Java code into equivalent Python:

```Python
class NonToolbarMultiStateAction:
    def __init__(self, name: str, owner: str):
        super().__init__(name, owner)

# Note that there's no direct equivalent to Java's generics in Python.
```

This Python class is a simple translation of the given Java code. It does not include any specific functionality related to "drop-down menu" or "EventTrigger", as these are concepts more relevant to GUI programming and may require additional libraries (like Tkinter, PyQt, etc.) that were not included here.

The `__init__` method is equivalent to the constructor in Java, where it initializes an instance of this class. The `super().__init__(name, owner)` call invokes the parent class's constructor (`MultiStateDockingAction`) with the provided arguments.