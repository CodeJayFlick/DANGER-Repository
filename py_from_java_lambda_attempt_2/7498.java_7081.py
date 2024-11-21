Here is the translation of the Java code to Python:

```Python
class FGLayout:
    def clone_layout(self):
        # implement this method in your subclass
        pass

    def get_visual_graph(self) -> 'FunctionGraph':
        # implement this method in your subclass
        return None


# Note: In Python, we don't have direct equivalent of Java's interface.
# Instead, you can use abstract base class (ABC) to achieve similar functionality.

from abc import ABC, abstractmethod

class FGLayout(ABC):
    @abstractmethod
    def clone_layout(self):
        pass

    @abstractmethod
    def get_visual_graph(self) -> 'FunctionGraph':
        return None


```

Note that the Python code does not have a direct equivalent of Java's interface. Instead, you can use abstract base classes (ABCs) to achieve similar functionality. In this case, we define an `FGLayout` class as an ABC with two abstract methods: `clone_layout` and `get_visual_graph`.