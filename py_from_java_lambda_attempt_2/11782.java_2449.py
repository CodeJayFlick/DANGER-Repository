Here's your Java code translated into Python:

```Python
class SpaceQuality:
    def __init__(self, name):
        self.name = name
        self.type = 'ram_space'
        self.size = 0
        self.wordsize = 1
        self.isdefault = False

    def __str__(self):
        return f"sq:{{name={self.name}, type={self.type}, size={self.size}, wordsize={self.wordsize}, isdefault={self.isdefault}}}"
```

This Python code defines a class `SpaceQuality` with the same attributes and methods as your Java code. The constructor (`__init__`) initializes these attributes, and the `__str__` method returns a string representation of an instance of this class.