Here is the translation of the Java code to Python:
```
class IntegerColumnAdapter:
    def get_value_class(self):
        return int

    def get_key_value(self, rec):
        key_field = rec.get_key_field()
        if isinstance(key_field, int):
            return int(key_field)
        else:
            raise ValueError("Expected IntField")

    def get_value(self, rec, col):
        return int(rec.get_int_value(col))
```
Note that I've used the `int` type in Python to represent integers, and removed the explicit `new Integer()` constructor calls. Additionally, I've replaced the Java-style method names with more conventional Python naming conventions (e.g., `get_key_value` instead of `getKeyValue`).