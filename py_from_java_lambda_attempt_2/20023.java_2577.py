Here is the translation of the Java code to Python:
```
import collections

class SimpleClassResolver:
    def __init__(self):
        self.classes = collections.OrderedDict()

    def register_class(self, c: type, id: str) -> None:
        old_id = self.classes.get(c)
        if old_id is not None and old_id != id:
            raise ValueError(f"Changed ID of {c.__name__} from {old_id} to {id}")
        self.classes[c] = id

    def get_class(self, id: str) -> type | None:
        return next((k for k, v in self.classes.items() if v == id), None)

    def get_id(self, c: type) -> str | None:
        return self.classes.get(c)
```
Note that I used the `collections.OrderedDict` to implement a bidirectional map (like Java's `BidiMap`) and Python's built-in dictionary methods (`get`, `items`, etc.) instead of custom classes.