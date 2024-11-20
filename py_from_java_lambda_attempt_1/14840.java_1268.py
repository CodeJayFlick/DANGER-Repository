Here is the translation of the given Java code into Python:

```Python
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class CustomerRole:
    """Key abstraction for segregated roles."""
```

Note that in Python, we don't need to specify a package name or import statements like `from` and `import`. Also, the concept of abstract classes is not directly available in Python. Instead, you can use inheritance with an abstract base class (ABC) from the built-in module `abc`, but it's generally considered more idiomatic to define interfaces using protocols or duck typing.

Here's how you could implement a similar idea using ABC:

```Python
from abc import ABC, abstractmethod

class CustomerRole(ABC):
    """Key abstraction for segregated roles."""

    @abstractmethod
    def do_something(self):
        pass  # You must override this method in subclasses.
```

In Python, the concept of "abstract" is more related to interfaces than classes.