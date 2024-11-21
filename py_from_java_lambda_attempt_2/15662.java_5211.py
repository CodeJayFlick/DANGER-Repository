Here is the translation of the Java code to Python:
```
import random

class HpCategorical:
    def __init__(self, name: str, categories):
        self.name = name
        self.categories = categories

    def random(self) -> object:
        return random.choice(list(self.categories))

    def __str__(self) -> str:
        return f"HPCategorical{{categories={self.categories}, name='{self.name}'}}"
```
Note that I've used the `f` string notation to create a formatted string in the `__str__` method, which is equivalent to Java's `toString()` method.