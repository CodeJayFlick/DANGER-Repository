Here's the translation of the given Java interface into Python:

```Python
class EditListener:
    def __init__(self):
        pass

    def edit_completed(self, new_text: str) -> None:
        """Notifies the listener of the text entered by the user when a text edit is completed."""
        ...
```

Note that in Python, we don't have an equivalent to Java's `interface` keyword. Instead, we define a class with methods that must be implemented if you want to use this interface.

Also note that there are no explicit type declarations for variables or method parameters in Python like there are in Java.