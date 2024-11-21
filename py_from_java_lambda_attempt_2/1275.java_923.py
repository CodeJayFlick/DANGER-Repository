Here is the translation of the given Java code into Python:

```Python
class AbstractGdbEventWithStateChange:
    def __init__(self, tail):
        self.reason = None
        super().__init__(tail)
        try:
            self.reason = GdbReason.get_reason(self.info())
        except Exception as e:
            print(f"Error parsing reason: {e}")

    @property
    def reason_(self):
        return self.reason

    def new_state(self) -> 'GdbState':
        pass  # abstract method, must be implemented by subclass


class GdbReason:
    @staticmethod
    def get_reason(tail):
        raise NotImplementedError("This function is not yet implemented")
```

Please note that the `get_reason` and `new_state` methods are currently just placeholders in Python. In Java, these were static methods defined within a class (`GdbReason`). However, since there's no direct equivalent of static classes or methods in Python, I've wrapped them into instance methods instead.

Also, error handling is different between the two languages. While Java has built-in support for exceptions and `try-catch` blocks, Python uses try-except blocks to catch exceptions.