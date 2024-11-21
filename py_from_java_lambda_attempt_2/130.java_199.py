Here is the translation of the Java code to Python:
```python
class StaticMappingRow:
    BIT64 = 2**64

    def __init__(self, mapping):
        self.mapping = mapping

    @property
    def mapping(self):
        return self.mapping

    @property
    def trace(self):
        return self.mapping.get_trace()

    @property
    def trace_address(self):
        return self.mapping.min_trace_address

    @property
    def static_program_url(self):
        return self.mapping.static_program_url

    @property
    def static_address(self):
        return self.mapping.static_address

    @property
    def length(self):
        return self.mapping.length

    @property
    def big_length(self):
        length = self.mapping.length
        if length == 0:
            return BIT64
        elif length < 0:
            return BigInteger(length).add(BIT64)
        else:
            return BigInteger(length)

    @property
    def shift(self):
        return self.mapping.shift

    @property
    def lifespan(self):
        return self.mapping.lifespan
```
Note that I used the `@property` decorator to create read-only properties for each attribute, which is equivalent to Java's getter methods.