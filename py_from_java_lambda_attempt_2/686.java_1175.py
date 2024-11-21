Here is the translation of the Java code to Python:
```
class DbgBreakpointDeletedEvent:
    def __init__(self, info):
        super().__init__(info)
        self.number = info.get_number()

    @property
    def number(self):
        return self._number

# Note: In Python, we don't need a separate class for the breakpoint information,
# as it can be represented as a simple dictionary or object.
class DbgBreakpointInfo:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    @property
    def get_number(self):
        return self.number

# Example usage:
info = DbgBreakpointInfo(number=123)
event = DbgBreakpointDeletedEvent(info)
print(event.number)  # prints 123
```
Note that I've used Python's built-in `super()` function to call the parent class constructor, and also used property decorators (`@property`) to create getter methods for the `number` attribute. Additionally, I've represented the breakpoint information as a simple dictionary-like object using the `DbgBreakpointInfo` class.