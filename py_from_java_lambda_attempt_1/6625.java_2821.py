Here is the translation of the given Java interface into a Python equivalent:

```Python
from abc import ABCMeta, abstractmethod
import xml.etree.ElementTree as ET


class FuncDB(metaclass=ABCMeta):
    @abstractmethod
    def query(self, func) -> list:
        pass

    @abstractmethod
    def restore_xml(self, parser: ET._ElementParser):
        pass

    @abstractmethod
    def save_xml(self, fwrite):
        pass
```

Note that in Python, we don't have direct equivalent of Java's interface. Instead, we use abstract base classes (ABCs) to define an abstract class with one or more pure virtual methods. The `@abstractmethod` decorator is used to indicate that a method must be implemented by any subclass.

The rest of the code remains similar in Python and Java, except for some minor differences such as:

- In Python, we use `list` instead of `ArrayList`.
- We don't have direct equivalent of Java's `IOException`, so it was removed.
- The type hinting is different between Java and Python.