Here is the translation of the given Java code into Python:

```Python
class Wizard:
    def __init__(self, name: str):
        self.name = name

    def __str__(self) -> str:
        return self.name


# Example usage:
wizard1 = Wizard("Gandalf")
print(wizard1)
```

In this translation, I have used Python's class-based object-oriented programming to create a `Wizard` class. The constructor (`__init__`) takes in the wizard's name and assigns it to an instance variable named `name`. 

The `__str__` method is overridden to return the value of the `name` attribute when called on the `wizard1` object, which can be printed directly using the print function.

Note that Python does not have a direct equivalent for Java's `@RequiredArgsConstructor`, but it achieves similar functionality through its constructor and class definition.