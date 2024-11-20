Here is the translation of the Java interface `EmulatorLoadData` to a Python class:

```python
class EmulatorLoadData:
    def get_memory_load_image(self):
        # implement this method in your subclass
        pass

    def get_initial_register_state(self):
        # implement this method in your subclass
        pass

    def view(self) -> None:
        return None  # default implementation, override if needed
```

Note that I've used Python's `pass` statement to indicate where the methods should be implemented by a subclass. In Java, you would typically throw an exception or return some kind of "not implemented" value in this case, but Python doesn't have built-in support for exceptions like Java does.

Also, I translated the `getView()` method to use Python's syntax for returning values from functions (`-> None` indicates that the function returns no value).