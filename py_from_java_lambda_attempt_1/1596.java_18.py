Here is the translation of the given Java code into equivalent Python:

```Python
class LldbCommandErrorEvent:
    def __init__(self):
        pass

    @classmethod
    def from_message(cls, message: str) -> 'LldbCommandErrorEvent':
        return cls(message)

    def new_state(self) -> int:
        return 1


# Note that Python does not have a direct equivalent of Java's StateType enum.
# In this translation, I used an integer value (1 in this case), which is commonly
# used to represent states or modes in Python. If you need more specific state types,
# consider using Python's built-in enum module.

```

This code defines a class `LldbCommandErrorEvent` with two methods: the constructor (`__init__`) and the static method `from_message`. The `new_state` method is an override of Java's equivalent, which returns an integer value.