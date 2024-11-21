Here is the translation of the Java code to Python:
```
class SpecificSymbol:
    def __init__(self, location):
        super().__init__(location)

    def __init__(self, location, nm):
        super().__init__(location, nm)

    def get_varnode(self) -> object:  # Note: VarnodeTpl is not a built-in Python type
        pass  # Abstract method implementation left to subclass

class TripleSymbol:
    def __init__(self, location):  # Assuming this class exists in the translation
        pass

from ghidra import Location  # Assuming this module exists and has a Location class

# Note: The rest of the code (semantics, grammar) is not translated as it's not provided.
```
Note that I had to make some assumptions about the `TripleSymbol` class and the `Location` object, as they were not defined in the original Java code. Additionally, I left the implementation of the abstract method `get_varnode()` empty, as it should be implemented by a subclass.