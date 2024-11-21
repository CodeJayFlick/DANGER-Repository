Here is the translation of the Java code to Python:
```
class DBTraceShiftedReference:
    def __init__(self, entry):
        super().__init__(entry)

    @property
    def shift(self):
        return int(entry.ext)

    @property
    def value(self):
        return (entry.to_address.get_offset() >> entry.ext)
```
Note that I've used Python's property decorator to create read-only properties for `shift` and `value`, which are equivalent to the getter methods in Java.