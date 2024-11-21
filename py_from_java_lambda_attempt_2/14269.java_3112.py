Here is the translation of the Java enum `MenuItem` to a Python class:

```python
class MenuItem:
    HOME = ("Home",)
    PRODUCTS = ("Products",)
    COMPANY = ("Company",)

    def __init__(self, title):
        self.title = title

    def __str__(self):
        return self.title[0]
```

Note that in Python, we don't have an exact equivalent to Java's enum. Instead, we can use a class with static variables and methods. In this case, I've used tuples as the values for each `MenuItem` instance, since strings are immutable in Python.

The `__init__` method is similar to the constructor in Java, where it initializes the object with its title. The `__str__` method returns a string representation of the object, which is equivalent to the `toString()` method in Java.