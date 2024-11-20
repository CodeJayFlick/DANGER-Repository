Here is the translation of the Java enum class `LSHMemoryModel` to a Python equivalent:
```python
class LSHMemoryModel:
    SMALL = ("Small (slower)", 10, 0.97, 0.75)
    MEDIUM = ("Medium", 13, 0.97, 0.75)
    LARGE = ("Large (faster)", 16, 0.97, 0.75)

    def __init__(self, label, k, probability_threshold, tau_bound):
        self.label = label
        self.k = k
        self.probability_threshold = probability_threshold
        self.tau_bound = tau_bound

    @property
    def label(self):
        return self._label

    @property
    def k(self):
        return self._k

    @property
    def probability_threshold(self):
        return self._probability_threshold

    @property
    def tau_bound(self):
        return self._tau_bound

    def __str__(self):
        return self.label
```
Note that I used Python's `class` syntax to define the equivalent of Java's enum class. The attributes are defined as instance variables, and the methods (getters) are implemented using Python's property decorator.

The `__init__` method is similar to the constructor in Java, where we initialize the object with its properties.

I also used the `@property` decorator to implement getter methods for each attribute, which allows us to access them like attributes.