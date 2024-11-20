Here is the translation of the given Java code into Python:

```Python
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class ZoomVisitor:
    def visit(self, zoom):
        pass


from abc import ABC, abstractmethod

class ModemVisitor(ABC):
    @abstractmethod
    def visit(self, modem):
        pass
```

Note that in Python, we don't have a direct equivalent of Java's `interface` keyword. Instead, we use classes with all methods declared as abstract (i.e., without an implementation). This is achieved by inheriting from the built-in `ABC` class and using the `@abstractmethod` decorator on those methods.

Also note that Python doesn't require explicit type declarations for variables or method parameters like Java does.