Here is the translation of the Java code to Python:

```Python
class LanguageID:
    def __init__(self, id):
        if not id:
            raise ValueError("id cannot be empty or null")
        self.id = id

    def get_id_as_string(self):
        return self.id

    def __hash__(self):
        prime = 31
        result = 1
        result = prime * result + (0 if self.id is None else hash(self.id))
        return result

    def __eq__(self, other):
        if self is other:
            return True
        if other is None or not isinstance(other, LanguageID):
            return False
        if self.id is None and other.id is not None:
            return False
        elif self.id != other.id:
            return False
        return True

    def __str__(self):
        return str(self.id)

    def __lt__(self, other):
        return self.id < other.id


# Example usage:

lang1 = LanguageID("x86:LE:32:default")
lang2 = LanguageID("8051:BE:16:default")

print(lang1.get_id_as_string())  # prints "x86:LE:32:default"
print(lang2.get_id_as_string())  # prints "8051:BE:16:default"

# Note that the __lt__ method is not used in this example, but it's included as part of the translation.
```

This Python code defines a `LanguageID` class with similar methods to the Java original. The main differences are:

- In Python, we don't need to specify types for variables or function parameters (e.g., `String id`, etc.). Instead, we rely on duck typing and type hints where necessary.
- We use the built-in `hash()` function instead of implementing our own hash code calculation.
- We define a custom comparison method (`__lt__`) in Python because Java's Comparable interface is not directly translatable to Python.