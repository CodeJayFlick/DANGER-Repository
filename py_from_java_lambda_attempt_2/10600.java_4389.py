Here is the translation of the given Java code into equivalent Python:

```Python
class XmlParseException(Exception):
    def __init__(self, message):
        super().__init__(message)

    def __init__(self, message, t):
        super().__init__(message, t)
```

Note that in Python, we don't need to specify the `public` access modifier as it is not applicable. Also, there's no direct equivalent of Java's `package` declaration in Python.