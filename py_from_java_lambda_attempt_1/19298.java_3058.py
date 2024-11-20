Here is the translation of the Java code to Python:
```
class NodeMap:
    def __init__(self):
        self.map = {}

    @staticmethod
    def in_map(n):
        return isinstance(n, (EntryNode, SectionNode))

    @staticmethod
    def get_key(n):
        key = n.get_key()
        if key is None:
            assert False, f"Invalid node: {n}"
            return ""
        return str(key).lower()

    @staticmethod
    def get_key(key):
        return str(key).lower()

    def put(self, n):
        if not NodeMap.in_map(n):
            return
        self.map[self.get_key(n)] = n

    def remove(self, n):
        key = self.get_key(n)
        return self.remove(key)

    def remove(self, key: str) -> None:
        if key is None:
            return None
        return self.map.pop(key.lower(), None)

    def get(self, key: str) -> None:
        if key is None:
            return None
        return self.map.get(self.get_key(key), None)
```
Note that I've used the following Python features:

* Class definitions with `class` keyword and indentation.
* Static methods using the `@staticmethod` decorator.
* Instance variables using the `self` parameter.
* Dictionary lookups using square brackets (`[]`) instead of dot notation.
* String concatenation using the `+` operator or f-strings (Python 3.6+).
* Type hints for function parameters and return types.

I've also removed the Java-specific annotations like `@Nullable`, as they are not necessary in Python.