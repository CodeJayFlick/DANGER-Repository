Here is the translation of the Java code to Python:

```Python
class Dragon:
    def __init__(self):
        self.__init__("Dragon", "LARGE", "FLYING", "RED", 39300.0)

    def __init__(self, mass: float):
        super().__init__("Dragon", "LARGE", "FLYING", "RED", mass)
```

Note that Python does not have a direct equivalent to Java's `package` statement or the concept of classes in separate files. The above code is written as a single class definition.

Also, note that Python uses double underscore (`__`) for private variables and methods (not exactly like Java), but it doesn't enforce encapsulation strictly unlike Java.