Here is the translation of the Java code to Python:
```python
import collections
from typing import Any, Dict, List

class ElementTrackingListener:
    def __init__(self, val_type: type):
        self.val_type = val_type
        self.elements: Dict[str, Any] = {}
        self.size: int = 0
        self.wait_elems: Dict[str, Any] = {}

    def ref_element(self, index: str) -> Any:
        elem = self.elements.get(index)
        if elem is None:
            return None
        return elem

    def elements_changed(self, parent: Any, removed: List[Any], added: Dict[Any, Any]) -> None:
        for key in list(removed):
            del self.elements[key]
        for key, value in added.items():
            self.elements[key] = value
        self.size = len(self.elements)

    def put_all(self, update: Dict[Any, Any]) -> None:
        for key, value in update.items():
            val = self.val_type(value)
            self.elements[key] = val
            if key in self.wait_elems:
                ref = self.wait_elems.pop(key)
                ref.set(val, None)

    def __str__(self) -> str:
        return f"ElementTrackingListener(size={self.size}, elements={self.elements})"
```
Note that I used the `typing` module to define type hints for Python 3.5 and later versions. If you're using an earlier version of Python, you can remove these type hints.

Also, I replaced Java's `TreeMap`, `HashMap`, and `AsyncReference` classes with their equivalent Python constructs: dictionaries (`{}`) and the built-in `set()` method for asynchronous operations (not actually used in this code).