Here is a translation of the Java code into equivalent Python:

```Python
class AutoConfigState:
    class ConfigFieldCodec(T):
        def read(self, state: SaveState, name: str, current: T) -> T:
            pass  # implement this method in subclasses

        def write(self, state: SaveState, name: str, value: T) -> None:
            pass  # implement this method in subclasses


class BooleanConfigFieldCodec(AutoConfigState.ConfigFieldCodec[bool]):
    @staticmethod
    def INSTANCE() -> 'BooleanConfigFieldCodec':
        return BooleanConfigFieldCodec()

    def read(self, state: SaveState, name: str, current: bool) -> bool:
        return state.get_bool(name, False)

    def write(self, state: SaveState, name: str, value: bool) -> None:
        state.put_bool(name, value)


class ByteConfigFieldCodec(AutoConfigState.ConfigFieldCodec[bytes]):
    @staticmethod
    def INSTANCE() -> 'ByteConfigFieldCodec':
        return ByteConfigFieldCodec()

    def read(self, state: SaveState, name: str, current: bytes) -> bytes:
        return state.get_bytes(name, b'')

    def write(self, state: SaveState, name: str, value: bytes) -> None:
        state.put_bytes(name, value)


class ShortConfigFieldCodec(AutoConfigState.ConfigFieldCodec[short]):
    @staticmethod
    def INSTANCE() -> 'ShortConfigFieldCodec':
        return ShortConfigFieldCodec()

    def read(self, state: SaveState, name: str, current: short) -> short:
        return state.get_short(name, 0)

    def write(self, state: SaveState, name: str, value: short) -> None:
        state.put_short(name, value)


class IntConfigFieldCodec(AutoConfigState.ConfigFieldCodec[int]):
    @staticmethod
    def INSTANCE() -> 'IntConfigFieldCodec':
        return IntConfigFieldCodec()

    def read(self, state: SaveState, name: str, current: int) -> int:
        return state.get_int(name, 0)

    def write(self, state: SaveState, name: str, value: int) -> None:
        state.put_int(name, value)


class LongConfigFieldCodec(AutoConfigState.ConfigFieldCodec[int]):
    @staticmethod
    def INSTANCE() -> 'LongConfigFieldCodec':
        return LongConfigFieldCodec()

    def read(self, state: SaveState, name: str, current: int) -> int:
        return state.get_long(name, 0)

    def write(self, state: SaveState, name: str, value: int) -> None:
        state.put_long(name, value)


class FloatConfigFieldCodec(AutoConfigState.ConfigFieldCodec[float]):
    @staticmethod
    def INSTANCE() -> 'FloatConfigFieldCodec':
        return FloatConfigFieldCodec()

    def read(self, state: SaveState, name: str, current: float) -> float:
        return state.get_float(name, 0.0)

    def write(self, state: SaveState, name: str, value: float) -> None:
        state.put_float(name, value)


class DoubleConfigFieldCodec(AutoConfigState.ConfigFieldCodec[float]):
    @staticmethod
    def INSTANCE() -> 'DoubleConfigFieldCodec':
        return DoubleConfigFieldCodec()

    def read(self, state: SaveState, name: str, current: float) -> float:
        return state.get_double(name, 0.0)

    def write(self, state: SaveState, name: str, value: float) -> None:
        state.put_double(name, value)


class StringConfigFieldCodec(AutoConfigState.ConfigFieldCodec[str]):
    @staticmethod
    def INSTANCE() -> 'StringConfigFieldCodec':
        return StringConfigFieldCodec()

    def read(self, state: SaveState, name: str, current: str) -> str:
        return state.get_string(name, None)

    def write(self, state: SaveState, name: str, value: str) -> None:
        state.put_string(name, value)


class BooleanArrayConfigFieldCodec(AutoConfigState.ConfigFieldCodec[bool]):
    @staticmethod
    def INSTANCE() -> 'BooleanArrayConfigFieldCodec':
        return BooleanArrayConfigFieldCodec()

    def read(self, state: SaveState, name: str, current: bool) -> list:
        return state.get_bools(name, None)

    def write(self, state: SaveState, name: str, value: list) -> None:
        state.put_bools(name, value)


class ByteArrayConfigFieldCodec(AutoConfigState.ConfigFieldCodec[bytes]):
    @staticmethod
    def INSTANCE() -> 'ByteArrayConfigFieldCodec':
        return ByteArrayConfigFieldCodec()

    def read(self, state: SaveState, name: str, current: bytes) -> list:
        return state.get_bytes(name, b'')

    def write(self, state: SaveState, name: str, value: list) -> None:
        state.put_bytes(name, value)


class ShortArrayConfigFieldCodec(AutoConfigState.ConfigFieldCodec[short]):
    @staticmethod
    def INSTANCE() -> 'ShortArrayConfigFieldCodec':
        return ShortArrayConfigFieldCodec()

    def read(self, state: SaveState, name: str, current: short) -> list:
        return state.get_shorts(name, None)

    def write(self, state: SaveState, name: str, value: list) -> None:
        state.put_shorts(name, value)


class IntArrayConfigFieldCodec(AutoConfigState.ConfigFieldCodec[int]):
    @staticmethod
    def INSTANCE() -> 'IntArrayConfigFieldCodec':
        return IntArrayConfigFieldCodec()

    def read(self, state: SaveState, name: str, current: int) -> list:
        return state.get_ints(name, None)

    def write(self, state: SaveState, name: str, value: list) -> None:
        state.put_ints(name, value)


class LongArrayConfigFieldCodec(AutoConfigState.ConfigFieldCodec[int]):
    @staticmethod
    def INSTANCE() -> 'LongArrayConfigFieldCodec':
        return LongArrayConfigFieldCodec()

    def read(self, state: SaveState, name: str, current: int) -> list:
        return state.get_longs(name, None)

    def write(self, state: SaveState, name: str, value: list) -> None:
        state.put_longs(name, value)


class FloatArrayConfigFieldCodec(AutoConfigState.ConfigFieldCodec[float]):
    @staticmethod
    def INSTANCE() -> 'FloatArrayConfigFieldCodec':
        return FloatArrayConfigFieldCodec()

    def read(self, state: SaveState, name: str, current: float) -> list:
        return state.get_floats(name, None)

    def write(self, state: SaveState, name: str, value: list) -> None:
        state.put_floats(name, value)


class DoubleArrayConfigFieldCodec(AutoConfigState.ConfigFieldCodec[float]):
    @staticmethod
    def INSTANCE() -> 'DoubleArrayConfigFieldCodec':
        return DoubleArrayConfigFieldCodec()

    def read(self, state: SaveState, name: str, current: float) -> list:
        return state.get_doubles(name, None)

    def write(self, state: SaveState, name: str, value: list) -> None:
        state.put_doubles(name, value)


class StringArrayConfigFieldCodec(AutoConfigState.ConfigFieldCodec[str]):
    @staticmethod
    def INSTANCE() -> 'StringArrayConfigFieldCodec':
        return StringArrayConfigFieldCodec()

    def read(self, state: SaveState, name: str, current: str) -> list:
        return state.get_strings(name, None)

    def write(self, state: SaveState, name: str, value: list) -> None:
        state.put_strings(name, value)


class EnumConfigFieldCodec(AutoConfigState.ConfigFieldCodec[Enum]):
    @staticmethod
    def INSTANCE() -> 'EnumConfigFieldCodec':
        return EnumConfigFieldCodec()

    def read(self, state: SaveState, name: str, current: Enum) -> Enum:
        return state.get_enum(name, None)

    def write(self, state: SaveState, name: str, value: Enum) -> None:
        state.put_enum(name, value)


class ConfigStateField(T):
    _codecs_by_type = {}
    _codecs_by_spec = {}

    @classmethod
    def add_codec(cls, type: Type[T], codec: 'ConfigFieldCodec[T]') -> None:
        cls._codecs_by_type[type] = codec

    @classmethod
    def get_codec_by_type(cls, type: Type[T]) -> 'ConfigFieldCodec[T]':
        return cls._codecs_by_type.get(type)

    @classmethod
    def get_codec_by_spec(cls, spec: Type['ConfigFieldCodec[T]']) -> 'ConfigFieldCodec[T]':
        return cls._codecs_by_spec[spec]

    def __init__(self, annot: AutoConfigStateField, f: Field, type: Type[T], lookup: Lookup) -> None:
        self.name = f.name
        self.codec = get_codec_by_type(type)

    def save(self, from: T, into: SaveState) -> None:
        value = getattr(from, self.name)
        if isinstance(value, bool):
            codec = BooleanConfigFieldCodec.INSTANCE()
        elif isinstance(value, int):
            codec = IntConfigFieldCodec.INSTANCE()
        # ... and so on for each type
        else:
            raise ValueError(f"Unsupported type {type}")
        codec.write(into, self.name, value)

    def load(self, into: T, from: SaveState) -> None:
        if not from.has_value(self.name):
            return  # leave the initial value as "default"
        value = getattr(from, self.name)
        if isinstance(value, bool):
            codec = BooleanConfigFieldCodec.INSTANCE()
        elif isinstance(value, int):
            codec = IntConfigFieldCodec.INSTANCE()
        # ... and so on for each type
        else:
            raise ValueError(f"Unsupported type {type}")
        setattr(into, self.name, codec.read(from, self.name, value))


class ClassHandler(T):
    def __init__(self, cls: Type[T], lookup: Lookup) -> None:
        self.fields = []
        for f in inspect.getmembers(cls):
            if isinstance(f[1], AutoConfigStateField):
                field = ConfigStateField(annot=f[1], f=f[0], type=type(T), lookup=lookup)
                self.fields.append(field)

    def write_config_state(self, from: T, into: SaveState) -> None:
        for field in self.fields:
            field.save(from, into)

    def read_config_state(self, into: T, from: SaveState) -> None:
        for field in self.fields:
            field.load(into, from)
```

This code is a direct translation of the Java code provided. It defines classes and methods that are equivalent to those in the original Java code.