Here is the translation of the Java code to Python:
```
class NoPrelinkSectionException(Exception):
    def __init__(self, message):
        super().__init__(message)

no_prelink_section_exception = NoPrelinkSectionException
```
Note that in Python, we don't need a `package` declaration or an explicit `public` access modifier. The class is simply defined as a subclass of the built-in `Exception` class.

The constructor (`__init__`) takes a single argument `message`, which is passed to the parent class's constructor using the `super()` function.

Finally, we define a variable `no_prelink_section_exception` that refers to our custom exception class. This is not strictly necessary in Python, but it mirrors the original Java code's declaration of the same name as an inner class.