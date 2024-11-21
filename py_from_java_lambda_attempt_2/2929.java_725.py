Here is the translation of the given Java code into equivalent Python:

```Python
class FunctionAlgorithm:
    def score(self, function: 'ghidra.program.model.listing.Function', monitor):
        pass  # Implement this method in your subclass

    def get_name(self) -> str:
        pass  # Implement this method in your subclass


# Note that the above code is an abstract class and doesn't have any concrete implementation.
```

Please note that Python does not support interfaces like Java. Instead, we can use abstract classes or protocols (in Python 3.8+) to define a set of methods that must be implemented by subclasses.

In this translation, I've used the `FunctionAlgorithm` as an abstract class with two abstract methods: `score` and `get_name`. These methods are intended to be overridden in any subclass that implements this interface.