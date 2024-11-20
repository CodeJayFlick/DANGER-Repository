Here is the translation of the Java code into Python:

```Python
class OffsetSnap:
    def __init__(self, offset: int, snap: int):
        self.offset = offset
        self.snap = snap

    def __str__(self) -> str:
        return f"{self.snap},{self.offset}"

    def __eq__(self, other):
        if not isinstance(other, OffsetSnap):
            return False
        if self.offset != other.offset or self.snap != other.snap:
            return False
        return True

    def __hash__(self) -> int:
        return hash((self.offset, self.snap))


class URLDBFieldCodec:
    def __init__(self, object_type: type, field: Field, column: int):
        pass  # Not implemented in Python equivalent

    def encode(self, url: str) -> str:
        if not url:
            return None
        return str(url)

    def store(self, value: URL, f: StringField):
        f.set_string(encode(value))

    def do_store(self, obj: object, record: DBRecord):
        pass  # Not implemented in Python equivalent


class LanguageIDDBFieldCodec:
    def __init__(self, object_type: type, field: Field, column: int):
        pass  # Not implemented in Python equivalent

    def store(self, value: str, f: StringField):
        if not value:
            return None
        f.set_string(value)

    def do_store(self, obj: object, record: DBRecord):
        pass  # Not implemented in Python equivalent


class AbstractOffsetSnapDBFieldCodec:
    def __init__(self, object_type: type, field: Field, column: int):
        pass  # Not implemented in Python equivalent

    def encode(self, value: OffsetSnap) -> bytes:
        raise NotImplementedError("encode")

    def decode(self, arr: bytes) -> OffsetSnap:
        raise NotImplementedError("decode")


class OffsetThenSnapDBFieldCodec(AbstractOffsetSnapDBFieldCodec):
    def __init__(self, object_type: type, field: Field, column: int):
        super().__init__(object_type, field, column)

    def encode(self, value: OffsetSnap) -> bytes:
        buf = bytearray(16)
        struct.pack(">QQ", value.offset, value.snap ^ 2**63 - 1)
        return bytes(buf)

    def decode(self, arr: bytes) -> OffsetSnap:
        buf = memoryview(arr)
        offset, snap = struct.unpack_from(">QQ", buf)
        return OffsetSnap(offset, snap)


class RefTypeDBFieldCodec:
    def __init__(self, object_type: type, field: Field, column: int):
        pass  # Not implemented in Python equivalent

    def encode(self, value: str) -> bytes:
        if not value:
            return b""
        return value.encode()

    def decode(self, enc: bytes) -> str:
        return enc.decode()


def lower_endpoint(range_: Range[int]) -> int:
    if range_.has_lower_bound():
        return range_.lower_endpoint()
    else:
        return 2**63 - 1


def upper_endpoint(range_: Range[int]) -> int:
    if range_.has_upper_bound():
        return range_.upper_endpoint()
    else:
        return 2**64 - 1


def to_range(lower: int, upper: int) -> Range[int]:
    if lower == 0 and upper == (2**63 - 1):
        return all
    elif not lower and upper:
        return at_most(upper)
    elif lower and not upper:
        return at_least(lower)
    else:
        return closed(lower, upper)


def intersect(a: Range[int], b: Range[int]) -> bool:
    if a.is_connected(b) and not a.intersection(b).is_empty():
        return True
    return False


class DBTraceUtils:
    @staticmethod
    def make_way(data: object, span: Range[int], lifespan_setter: callable,
                 deleter: callable):
        if span.contains(lower_endpoint(span)):
            deleter(data)
            return
        lifespan_setter(data, to_range(data.getY1(), lower_endpoint(span) - 1))


def covariant_iterator(it: Iterator[object]) -> Iterator[object]:
    return it


class AddressSetView:
    def __init__(self, factory: object, start: int, forward: bool):
        pass  # Not implemented in Python equivalent

    @staticmethod
    def get_address_set(factory: object, start: int, end: int) -> object:
        all = factory.get_address_set()
        if forward:
            return factory.get_address_set(start, all.max)
        else:
            return factory.get_address_set(all.min, start)


def to_range(min_: int, max_: int) -> Range[int]:
    if min_ > max_:
        raise ValueError("min must precede max")
    return AddressRangeImpl(min_, max_)
```

Please note that the Python code is not a direct translation of Java. Some parts are missing or simplified due to differences in how Python and Java handle certain things, such as exceptions, type systems, etc.