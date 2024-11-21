Here is the translation of the given Java code into Python:

```Python
import unittest

class LockingException(Exception):
    def __init__(self, message):
        super().__init__(message)

def test_exception():
    try:
        raise LockingException("test")
    except LockingException as e:
        assert e.args[0] == "test"

if __name__ == "__main__":
    unittest.main()
```

Note that Python does not have a direct equivalent to Java's `@Test` annotation. Instead, we use the built-in `unittest` module and define our test function with the same name as the method in the original code (`test_exception`).