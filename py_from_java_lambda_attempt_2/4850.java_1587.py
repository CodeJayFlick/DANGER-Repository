Here is the translation of the given Java code into equivalent Python:

```Python
class ThreadStatePPC:
    PPC_THREAD_STATE = 1
    PPC_FLOAT_STATE = 2
    PPC_EXCEPTION_STATE = 3
    PPC_VECTOR_STATE = 4
    PPC_THREAD_STATE64 = 5
    PPC_EXCEPTION_STATE64 = 6
    THREAD_STATE_NONE = 7

    def __init__(self):
        pass

    @classmethod
    def create_thread_state_ppc(cls, reader, is32bit) -> 'ThreadStatePPC':
        thread_state_ppc = cls()
        thread_state_ppc.init_thread_state_ppc(reader, is32bit)
        return thread_state_ppc

    def init_thread_state_ppc(self, reader: object, is32bit: bool):
        self.srr0 = reader.read(is32bit)
        self.srr1 = reader.read(is32bit)
        for i in range(31):
            setattr(self, f'r{i}', reader.read(is32bit))
        self.cr = reader.read()
        self.xer = reader.read(is32bit)
        self.lr = reader.read(is32bit)
        self.ctr = reader.read(is32bit)
        self.mq = reader.read(is32bit)
        self.vrsave = reader.read(is32bit)

    def read(self, reader: object, is32bit: bool) -> int:
        if is32bit:
            return reader.read() & 0xffffffff
        else:
            return reader.read()

    @property
    def instruction_pointer(self):
        return self.srr0

    def to_data_type(self) -> dict:
        data_type = {'category': 'MachConstants.DATA_TYPE_CATEGORY'}
        for attr in dir(self):
            if not attr.startswith('__'):
                value = getattr(self, attr)
                data_type[attr] = value
        return data_type


class StructureDataType(dict):
    def __init__(self, name: str, size: int):
        super().__init__()
        self['name'] = name
        self['size'] = size

    def add(self, dtype: str, attr_name: str, null_value=None) -> None:
        if null_value is not None:
            value = {'value': null_value}
        else:
            value = {}
        super().__setitem__(attr_name, value)
```

Please note that Python does not have direct equivalent of Java's `long` type. It has two types: `int` and `float`. The code above assumes that the values are 32-bit integers if `is32bit` is True; otherwise, they are 64-bit integers.