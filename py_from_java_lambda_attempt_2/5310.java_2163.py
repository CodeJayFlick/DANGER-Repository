Here is the translation of the Java code to Python:
```
class ExporterException(Exception):
    def __init__(self, msg=None, cause=None):
        if msg:
            super().__init__(msg)
        elif cause:
            super().__init__(cause)

# Example usage
try:
    # some code that might raise an exception
except Exception as e:
    raise ExporterException("Custom error message", e) from None

```
Note that in Python, we don't need to specify the `public` access modifier since everything is public by default. Also, the constructor (`__init__`) takes two optional arguments: `msg` and `cause`. If both are provided, it will raise an exception with a custom message and the original cause.