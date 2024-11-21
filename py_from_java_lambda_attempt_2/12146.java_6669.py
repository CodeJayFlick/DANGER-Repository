Here is the translation of the given Java code into Python:

```Python
class AddressOutOfBoundsException(Exception):
    """An AddressOutOfBoundsException indicates that the Address is being used 
       to address Memory which does not exist."""
    
    def __init__(self, message="Address not contained in memory"):
        super().__init__(message)
```

Note: In Python, we don't need a separate class for exceptions like Java. We can directly inherit from `Exception` and define our own exception type.