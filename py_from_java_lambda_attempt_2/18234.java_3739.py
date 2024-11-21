Here is the translation of the Java interface `IBinaryExpression` to a Python class:

```python
class IBinaryExpression:
    def get_left(self):
        pass  # implement this method in your subclass

    def get_right(self):
        pass  # implement this method in your subclass

    def set_left(self, left_expression):
        pass  # implement this method in your subclass

    def set_right(self, right_expression):
        pass  # implement this method in your subclass
```

Note that Python does not have a direct equivalent to Java's interface concept. Instead, we define an abstract base class (ABC) using the `abc` module from the standard library. However, since you only provided the original Java code and no specific requirements for implementing the ABC in Python, I simply defined a regular Python class with placeholder methods that need to be implemented by any subclass.

If you want to create a concrete implementation of this interface in Python, you would define another class that inherits from `IBinaryExpression` and implements its abstract methods.