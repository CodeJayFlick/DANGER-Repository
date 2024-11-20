Here is the translation of the Java code to Python:
```
class AssemblyResolutionResults:
    def __init__(self):
        self.resolutions = set()

    @classmethod
    def singleton(cls, rc):
        return cls({rc})

    def add(self, ar):
        return ar in self.resolutions.add(ar)

    def absorb(self, that):
        self.resolutions.update(that.resolutions)

    def add_all(self, c):
        return self.resolutions.update(c)

    @property
    def resolutions(self):
        return frozenset(self.resolutions)
```
Note:

* In Python, we don't need to specify the type of a variable or method parameter.
* The `@classmethod` decorator is used to define a classmethod in Python. This allows us to create a new instance of the class using the `singleton` method.
* The `add`, `absorb`, and `add_all` methods are implemented differently than their Java counterparts, as sets in Python do not have an `add` or `addAll` method. Instead, we use the `update` method to add elements to a set.
* The `resolutions` property is defined using the `@property` decorator, which allows us to access the underlying set of resolutions as a frozen set (i.e., an immutable set).
* In Python, it's common to use descriptive variable names instead of abbreviations like `ar`.