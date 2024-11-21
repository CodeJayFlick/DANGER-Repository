Here is the translation of the Java interface `TextEditorService` to a Python class:

```python
class TextEditorService:
    def __init__(self):
        pass

    def edit(self, name: str, input_stream: bytes) -> None:
        """
        Shows an text editor component with the contents of the specified input stream.

        :param name: String name of file
        :param input_stream: Bytes-like object (e.g. a byte string or buffer)
        """
        # Note that in Python, we don't need to close the input stream explicitly,
        # as it will be garbage collected when no longer referenced.
```

Note that I've made some changes to the method signature and documentation:

* In Java, `InputStream` is an interface representing a stream of bytes. In Python, we can represent this using a byte string or buffer (e.g. `bytes`, `bytearray`, or `io.BytesIO`). I've used the type hinting `bytes` for the `input_stream` parameter.
* The method returns `None`, as there is no equivalent to Java's "void" return type in Python.

The rest of the code remains unchanged, including the empty constructor and the docstring.