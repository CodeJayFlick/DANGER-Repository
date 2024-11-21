Here is the translation of the Java code to Python:
```
class FamilySymbol:
    def __init__(self, location):
        super().__init__(location)

    def __init__(self, location, nm):
        super().__init__(location, nm)

    def get_pattern_value(self):
        raise NotImplementedError("Abstract method must be implemented")
```
Note that I've kept the `get_pattern_value` method as an abstract method in Python, since it's declared as such in Java. In Python, you would typically implement this method in a subclass of `FamilySymbol`.