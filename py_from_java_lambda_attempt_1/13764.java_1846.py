Here is the translation of the given Java code into Python:

```Python
class MobileProduct:
    def __init__(self):
        self._price = None

    @property
    def price(self):
        return self._price

    @price.setter
    def price(self, value):
        self._price = value
```

Please note that in Python, we don't have a direct equivalent of Java's `@Getter` and `@Setter`. Instead, we use the concept of properties (also known as getters and setters) to achieve similar functionality.