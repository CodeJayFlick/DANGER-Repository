Here is the translation of the given Java code into Python:

```Python
class Builder:
    def __init__(self):
        self.builders = {}

    def add(self, name: str, supplier) -> None:
        if not isinstance(name, str):
            raise TypeError("Name must be a string")
        self.builders[name] = supplier

# Example usage:
builder = Builder()
builder.add('gun', lambda: Gun())
```

In this Python code:

- The `Builder` class is defined with an initializer method (`__init__`) that initializes an empty dictionary called `builders`.
- A method named `add` is added to the `Builder` class. This method takes two parameters, a string (the name of the weapon) and a supplier function.
- In this example usage section, we create an instance of the `Builder`, add some builders with names 'gun' and 'laser', and then you can use these suppliers to get instances of guns or lasers.

Please note that Python does not have direct equivalent for Java's functional interfaces like Supplier. However, in this case, a lambda function is used as a supplier which provides the functionality similar to Java's Supplier interface.