Here is the translation of the Java interface `Document` into a Python class:

```python
from typing import Any, Dict, Stream

class Document:
    def put(self, key: str, value: Any) -> None:
        pass  # Implement this method in your subclass

    def get(self, key: str) -> Any:
        return None  # Return the default value or raise an exception if not found

    def children(self, key: str, constructor: callable) -> Stream[Any]:
        pass  # Implement this method in your subclass
```

Note that I've used Python's type hints to indicate the types of the `put`, `get`, and `children` methods. The `Stream` class is not a built-in Python class, so you may need to use an external library like `streamz` or implement it yourself.

Also, in Java, interfaces are abstract by default, whereas in Python, classes can be abstract using the `abc` module (Abstract Base Classes). However, since we're translating an interface into a class, I've chosen not to use the `abc` module here.