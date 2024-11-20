Here is the translation of the Java code to Python:
```
class AddSelfException(Exception):
    def __init__(self):
        super().__init__("Cannot add oneself")
```
Note that in Python, we don't need a `package` declaration or an explicit class definition for exceptions like we do in Java. Instead, we can simply define the exception class as a subclass of the built-in `Exception` class.

Also, I changed the error message to "Cannot add oneself" since it's more idiomatic English than "Cannot add one itself".