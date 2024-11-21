Here is the equivalent Python code:

```Python
class ExceptionStateX86_32:
    def __init__(self):
        self.trapno = None
        self.err = None
        self.faultvaddr = None

    @classmethod
    def from_binary_reader(cls, reader):
        try:
            trapno = int.from_bytes(reader.read(4), 'little')
            err = int.from_bytes(reader.read(4), 'little')
            faultvaddr = int.from_bytes(reader.read(4), 'little')
            return cls(trapno, err, faultvaddr)
        except Exception as e:
            raise

    def to_data_type(self):
        from dataclasses import make_dataclass
        X86_Exception_State32 = make_dataclass('X86_Exception_State32', 
                                                fields=[
                                                    ('trapno', int),
                                                    ('err', int),
                                                    ('faultvaddr', int)
                                                ])
        return X86_Exception_State32(*[getattr(self, field.name) for field in X86_Exception_State32.__data_class__.fields])
```

Note that Python does not have direct equivalent of Java's `StructConverter` and `DataType`. I used the built-in dataclass feature to create a simple class representation. The `from_binary_reader` method is designed to read from binary reader, but it assumes little-endian byte order for simplicity.