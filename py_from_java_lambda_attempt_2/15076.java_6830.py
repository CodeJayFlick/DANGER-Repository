Here is the translation of the given Java code into Python:

```Python
class PotatoPeelingTask:
    TIME_PER_POTATO = 200

    def __init__(self, num_potatoes):
        super().__init__(num_potatoes * self.TIME_PER_POTATO)

    def __str__(self):
        return f"{type(self).__name__} {super().__str__()}"
```

Note that Python does not have a direct equivalent to Java's `package` statement. In Python, you can use modules or packages as needed. The given code is written in the context of a class-based object-oriented programming style similar to Java.