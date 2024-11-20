Here is the translation of the given Java code into Python:

```Python
class EmptyCompositeException(Exception):
    """ Exception thrown if the composite data type is empty.
        Typically this will be thrown if the user tries to save or apply a 
        composite with no components."""
    
    def __init__(self, message="Data type is empty."):
        super().__init__(message)

    @classmethod
    def from_composite(cls, composite):
        """ Constructor
            @param composite the structure data type that is empty.
        """
        return cls(composite.get_display_name() + " is empty.")

# Example usage:
class Composite:
    def get_display_name(self):
        return "MyComposite"

composite = Composite()
try:
    # Some operation that might raise EmptyCompositeException
except EmptyCompositeException as e:
    print(e)
```

Please note that Python does not have direct equivalent of Java's `UsrException` class. Instead, we can use the built-in `Exception` class and create our own custom exception classes if needed.