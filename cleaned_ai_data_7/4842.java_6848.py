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
