Here is the translation of the given Java code into Python:

```Python
class PcodeXMLException(Exception):
    def __init__(self, msg, *args, **kwargs):
        if 'cause' in kwargs:
            super().__init__("XML comms: " + str(msg), *args, cause=kwargs['cause'])
        else:
            super().__init__("XML comms: " + str(msg))

# Example usage
try:
    # Some code that might raise an exception
except Exception as e:
    pcode_exception = PcodeXMLException("Error occurred", cause=e)
```

Note that Python does not have a direct equivalent to Java's `extends` keyword. Instead, we define the class `PcodeXMLException` by inheriting from the built-in `Exception` class in Python.

Also note that Python 3.x has changed its exception handling mechanism compared to earlier versions of Python (like Python 2.x). The code above is written for Python 3.x and later.