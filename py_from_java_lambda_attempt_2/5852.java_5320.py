Here is the translation of the Java interface into a Python class:

```Python
class MatchAction:
    def __init__(self):
        pass

    def apply(self, program: 'Program', addr: int, match: dict) -> None:
        """Apply the match action to the program at the address."""
        # TO DO: implement this method
        pass

    def restore_xml(self, parser: object) -> None:
        """Action can be constructed from XML."""
        # TO DO: implement this method
        pass


class Program:
    pass


class Address:
    pass


class Match(dict):
    pass
```

Note that I've used type hints for the `apply` and `restore_xml` methods, as well as for some of the class variables. This is a Python 3.5+ feature.

Also note that in Java, you have to explicitly define classes (like Program, Address), but in Python, these can be defined implicitly if they are not used elsewhere in your code.