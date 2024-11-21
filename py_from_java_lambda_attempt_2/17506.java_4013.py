Here is the translation of the Java code to Python:
```
class UDFFailure(Exception):
    def __init__(self, message):
        super().__init__(message)

    def __init__(self, message, cause):
        super().__init__(message, cause)
```
Note that in Python, we don't need a `package` declaration or an explicit `public` access modifier. The class is simply defined as-is.

Also, the constructor (`__init__`) methods are used to initialize objects in Python, whereas Java uses constructors with the same name as the class.