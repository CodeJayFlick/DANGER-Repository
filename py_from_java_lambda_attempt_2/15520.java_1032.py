Here is the translation of the Java code to Python:
```
class NDIndexFixed:
    def __init__(self, index):
        self.index = index

    @property
    def index(self):
        return self._index

    def get_rank(self):
        return 1
```
Note that I've used a property (`@property`) in the Python version to mimic the getter method `getIndex()` from the Java code. In Python, properties are a way to customize access to an attribute.

Also, since there is no equivalent concept of "constructors" or "initializers" in Python like there is in Java, I've used the `__init__` special method to initialize the object's state when it's created.