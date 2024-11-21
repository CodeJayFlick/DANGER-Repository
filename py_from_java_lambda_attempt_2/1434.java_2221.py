Here's a translation of the Java interface into Python:

```Python
class PtyEndpoint:
    def __init__(self):
        pass

    def get_output_stream(self) -> bytes:
        raise NotImplementedError("This end is not local")

    def get_input_stream(self) -> bytes:
        raise NotImplementedError("This end is not local")
```

Note that the `getOutputStream` and `getInputStream` methods in Java are replaced with equivalent Python functions. The `@return` and `@throws` comments were removed as they're not necessary for a Python function.