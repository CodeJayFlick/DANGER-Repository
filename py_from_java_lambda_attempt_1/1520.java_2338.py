Here is the translation of the given Java code into equivalent Python:

```Python
class DebugOutputCallbacks:
    def __init__(self):
        pass

    def output(self, mask: int, text: str) -> None:
        """The interface for receiving output callbacks"""
        # Your callback logic here
        print(f"Mask: {mask}, Text: {text}")
```

Note that Python does not have a direct equivalent to Java's `@FunctionalInterface` annotation. In Python, you can use functions or classes as first-class citizens and pass them around like any other object.

The provided code defines a class `DebugOutputCallbacks` with an `output` method that takes two parameters: `mask` (an integer) and `text` (a string). The method is designed to receive output callbacks, but in this Python translation, it simply prints the received mask and text.