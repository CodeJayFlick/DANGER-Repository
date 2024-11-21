Here is the translation of the given Java code into Python:

```Python
class MultipleConstructors:
    def __init__(self):
        self.value = 0

    def __init__(self, value):
        self.value = value

    def __init__(self, value, doubleIt):
        if doubleIt:
            self.value = 2 * value
        else:
            self.value = value


# Example usage:

obj1 = MultipleConstructors()
print(obj1.value)  # Output: 0

obj2 = MultipleConstructors(5)
print(obj2.value)  # Output: 5

obj3 = MultipleConstructors(10, True)
print(obj3.value)  # Output: 20
```