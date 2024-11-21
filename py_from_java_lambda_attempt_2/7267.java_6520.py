Here is the translation of the given Java code into equivalent Python:

```Python
class UID:
    def __init__(self, bytes):
        self.bytes = bytes

    def get_type(self):
        return "UID"

    def to_data_type(self) -> dict:
        structure = {"name": f"UID{len(self.bytes)}", "length": 0}
        array = {"type": "byte", "length": len(self.bytes), "name": "UID"}
        structure["children"] = [array]
        return structure

    def __str__(self):
        return str(self.bytes)
```

Please note that Python does not have direct equivalent of Java's `@Override` annotation. Also, the exception handling in Python is different from Java. In this translation, I've used a simple dictionary to represent the data type and its children (array).