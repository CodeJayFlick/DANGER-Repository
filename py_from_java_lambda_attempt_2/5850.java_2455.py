Here is the translation of the given Java code into Python:

```Python
class GenericMatchAction:
    def __init__(self, match_value):
        self.match_value = match_value

    @property
    def match_value(self):
        return self._match_value

    @match_value.setter
    def match_value(self, value):
        self._match_value = value


# Example usage:

class MyMatchValue:
    pass

action = GenericMatchAction(MyMatchValue())
print(action.match_value)  # prints: <__main__.MyMatchValue object at 0x7f5e6c3a4d30>
```

Please note that Python does not have a direct equivalent to Java's generics. The `GenericMatchAction` class in the provided code is defined as a generic class with type parameter `<T>`, which means it can work with any data type. In Python, we do not need such explicit declaration of types because it is dynamically typed language and allows for more flexibility.

In this translation, I have used a simple `class GenericMatchAction:` to define the equivalent of Java's generic class. The constructor (`__init__`) takes one argument which will be stored in an instance variable called `match_value`. 

I also added getter and setter methods (using Python's property decorator) for the `match_value` attribute, similar to how it is done in Java.

Finally, I provided a simple example of using this class with a custom data type (`MyMatchValue`).