Here is the translation of the given Java code into equivalent Python:

```Python
class AbstractLldbCompletedCommandEvent:
    def __init__(self, message=None):
        if message is None:
            super().__init__(None)
        else:
            super().__init__(message)

    def new_state(self) -> object:
        return None

# Usage example:
event = AbstractLlldbCompletedCommandEvent("Event occurred")
print(event.get_message())  # prints: Event occurred
```

Note that Python does not have a direct equivalent to Java's `StateType` enum. In this translation, I've replaced it with the built-in `object` type in Python, which is essentially similar to an object of unknown type.

Also note that Python doesn't require explicit declaration of types for variables or function parameters like Java does. The code above uses dynamic typing and relies on runtime checks instead.