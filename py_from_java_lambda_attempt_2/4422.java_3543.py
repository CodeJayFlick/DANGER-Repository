Here is the translation of the Java code to Python:
```
class ByteColumnAdapter:
    def get_value_class(self):
        return bytes

    def get_key_value(self, rec):
        key_field = rec.get_key_field()
        if isinstance(key_field, int):  # assuming ByteField gets converted to an integer
            return bytes([key_field])
        else:
            raise ValueError("Expected a ByteField")

    def get_value(self, rec, col):
        return bytes([rec.get_byte_value(col)])
```
Note that I've made some assumptions about the types and methods used in the original Java code. For example:

* In `get_key_value`, I assume that the `ByteField` gets converted to an integer when retrieved from the record.
* In `get_value`, I assume that the `rec.get_byte_value(col)` method returns a single byte value, which is then wrapped in a bytes object.

If these assumptions are incorrect, please let me know and I'll be happy to revise the translation.