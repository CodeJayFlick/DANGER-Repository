Here is the translation of the given Java interface into a Python class:

```Python
class Pointer:
    def __init__(self):
        pass

    def get_data_type(self) -> 'DataType':
        """Returns the "pointed to" data type"""
        pass  # Implement this method in your subclass

    @classmethod
    def new_pointer(cls, data_type: 'DataType') -> 'Pointer':
        """Creates a pointer to the indicated data type."""
        return cls()  # You would need to implement how you want to create a new Pointer instance.
```

Note that Python does not have direct support for interfaces like Java. Instead, we can use abstract base classes (ABCs) or protocols to define an interface. In this case, I've used the `class` keyword and defined two methods: one that returns the "pointed to" data type (`get_data_type`) and another method that creates a new pointer instance (`new_pointer`).