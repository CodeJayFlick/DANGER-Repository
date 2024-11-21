Here is the equivalent Python code:

```Python
class PackedDataOpcodes:
    kPEFPkDataZero = 0
    kPEFPkDataBlock = 1
    kPEFPkDataRepeat = 2
    kPEFPkDataRepeatBlock = 3
    kPEFPkDataRepeatZero = 4
    kPEFPkDataReserved5 = 5
    kPEFPkDataReserved6 = 6
    kPEFPkDataReserved7 = 7

    def __init__(self, value):
        self.value = value

    @property
    def value(self):
        return self._value

    @classmethod
    def get(cls, value):
        for opcode in cls.__dict__.values():
            if isinstance(opcode, PackedDataOpcodes) and opcode.value == value:
                return opcode
        raise ValueError("Invalid packed data opcode")
```

Note that Python does not have an exact equivalent to Java's enum type. The above code uses a class with static values instead.