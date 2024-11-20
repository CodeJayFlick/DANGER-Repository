Here is the translation of the Java interface `docking.help.HelpDescriptor` to Python:
```
class HelpDescriptor:
    def __init__(self):
        pass

    def get_help_object(self) -> object:
        """Returns the object for which help locations are defined."""
        raise NotImplementedError("Must be implemented by subclass")

    def get_help_info(self) -> str:
        """Returns a descriptive String about the help object that this descriptor represents."""
        raise NotImplementedError("Must be implemented by subclass")
```
Note that in Python, we don't have an explicit `interface` keyword like Java does. Instead, we define a class with abstract methods using the `raise NotImplementedError` statement.

Also, I used the `->` syntax to indicate the return type of each method, which is not strictly necessary but can be helpful for documentation and static analysis purposes.