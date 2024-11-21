Here is the translation of the Java enum class into a Python equivalent:

```Python
class Size:
    SMALL = ("small",)
    NORMAL = ("normal",)
    LARGE = ("large",)

    def __init__(self, title):
        self.title = title

    def __str__(self):
        return self.title
```

Note that in Python, we don't have an equivalent to Java's enum class. Instead, we can use a simple class with static variables and methods.