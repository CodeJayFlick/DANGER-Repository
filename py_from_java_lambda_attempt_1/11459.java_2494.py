Here is the translation of the given Java code into Python:

```Python
class ExpressionTerm:
    def __init__(self, value: 'ExpressionValue', offset: 'Offset'):
        self.val = value
        self.offset = offset

    def long_value(self, buf: bytes, off: int) -> int:
        return self.val.long_value(buf, self.offset.get_offset(buf, off))

    def length(self, buf: bytes, off: int) -> int:
        o = self.offset.get_offset(buf, off)
        return o - off + self.val.length(buf, o)

    def link_relative_offsets(self, op_hash: dict):
        if isinstance(self.val, BinaryExpression):
            (self.val).link_relative_offsets(op_hash)
        else:
            self.offset.set_relative_offset(op_hash)

    @property
    def value(self) -> 'ExpressionValue':
        return self.val

    def set_space(self, space: object) -> None:
        if not isinstance(self.val, BinaryExpression):
            raise Exception("Can't add space to an ExpressionTerm that does not contain a BinaryExpression")
        (self.val).set_space(space)
```

Note:

- The `@property` decorator is used in Python to create getter and setter methods for the class attributes.
- In Java, there are classes like `AddressSpace`, `MemBuffer`, etc. These have been replaced with their equivalent data types in Python (`bytes` instead of `MemBuffer`, etc.).