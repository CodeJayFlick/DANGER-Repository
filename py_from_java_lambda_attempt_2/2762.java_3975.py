Here is the translation of the Java code to Python:
```
class ComposedSleighUseropLibrary:
    def __init__(self, libraries):
        self.userops = {}
        for lib in libraries:
            for def_ in lib.get_userops().values():
                if self.userops.setdefault(def_.name, def_) is not None:
                    raise ValueError(f"Cannot compose libraries with conflicting definitions on {def_.name}")
        return

    @property
    def userops(self):
        return dict(self.__userops)

class SleighUseropDefinition:
    def __init__(self, name):
        self.name = name

class SleighUseropLibrary:
    def get_userops(self):
        # implement this method to return a dictionary of user ops
        pass
```
Note that I had to make some assumptions about the Python equivalent classes and methods. Specifically:

* The `SleighUseropDefinition` class has a single attribute `name`, which is set in its constructor.
* The `SleighUseropLibrary` class has a method `get_userops()` that returns a dictionary of user ops (which we assume will be implemented separately).
* I used the `setdefault` method to achieve similar behavior as Java's `put` method, which returns null if the key is already present.
* I used Python's built-in `dict` type to represent the map in Java.

Please note that this translation may not cover all edge cases or handle errors perfectly. It's intended to provide a rough equivalent of the original code in Python.