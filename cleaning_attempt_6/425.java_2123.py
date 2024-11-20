class DebugValue:
    def __init__(self):
        pass

    @property
    def bit_length(self):
        raise NotImplementedError("bitLength not implemented")

    @property
    def byte_length(self):
        raise NotImplementedError("byteLength not implemented")

    def get_debug_value_class(self):
        return self.__class__

    def decode_bytes(self, bytes: bytearray) -> 'DebugValue':
        raise NotImplementedError("decodeBytes not implemented")


@dataclasses.dataclass
@classmethod
def ForDebugValueType(cls, value_type: DebugValueType):
    pass


class DebugInt8Value(DebugValue):
    def __init__(self, value: int):
        self.value = value

    @property
    def byte_value(self) -> bytes:
        return [self.value]


class DebugInt16Value(DebugValue):
    def __init__(self, value: int):
        self.value = value


@dataclasses.dataclass
def ForDebugValueType(cls, value_type: DebugValueType):
    pass

# ... and so on for other classes (DebugInt32Value, DebugFloat32Value, etc.)
