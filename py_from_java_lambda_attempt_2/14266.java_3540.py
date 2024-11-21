Here is the translation of the given Java code into Python:

```Python
class Content:
    PRODUCTS = ("Products - This page lists the company's products.",)
    COMPANY = ("Company - This page displays information about the company.",)

    def __init__(self, title):
        self.title = title

    def __str__(self):
        return self.title


if __name__ == "__main__":
    print(Content.PRODUCTS[0])
    print(Content.COMPANY[0])
```

Note that Python does not have an equivalent to Java's `enum` keyword. Instead, we define a class with static variables and use the class itself as the enum values. The `__init__` method is used to initialize each instance of the class (although in this case it's not strictly necessary), and the `__str__` method is overridden to provide a string representation for each content item.