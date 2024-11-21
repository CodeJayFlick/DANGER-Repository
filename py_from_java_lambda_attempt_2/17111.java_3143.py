Here is the translation of the Java code to Python:
```
class FlushRuntimeError(Exception):
    def __init__(self, exception: Exception):
        super().__init__(str(exception))

serialVersionUID = 2249517655460110259
```
Note that:

* In Python, we don't need a `package` statement or an explicit class declaration. We can simply define the class.
* The `extends RuntimeException` part is not necessary in Python, as exceptions are first-class citizens and can be inherited from built-in types like `Exception`.
* The `private static final long serialVersionUID = 2249517655460110259L;` line is a Java-specific concept that doesn't have an equivalent in Python. I've simply defined the constant at the top level.
* In the constructor, we use the `super().__init__(str(exception))` syntax to initialize the exception with a string representation of the original exception.

That's it!