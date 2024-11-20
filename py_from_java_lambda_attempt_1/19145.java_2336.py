Here is the translation of the given Java code into equivalent Python:

```Python
class StringStoreWorker:
    class TestEnum(enum.Enum):
        YES = 1
        NO = 2
        NULL = 3

    INSTANCE = StringStoreWorker()

    def __init__(self):
        pass

    @staticmethod
    def with_state_and_id(state, value, contents_id):
        return f"{state}|{value}@{contents_id}"

    @staticmethod
    def with_id(value, contents_id):
        return f"{value}@{contents_id}"

    def to_store_on_reference_state(self, contents):
        i = contents.find('|')
        if i != -1:
            contents = contents[i + 1:]
        return bytes(contents.encode('utf-8'))

    def to_store_global_state(self, contents):
        i = contents.find('@')
        cid = contents[i:]
        i = contents.find('|')
        if i != -1:
            contents = contents[:i] + cid
        return bytes(contents.encode('utf-8'))

    def value_from_store(self, on_reference_value, global_state=None):
        if global_state is not None:
            return f"{self.strip_contents_id(global_state.decode('utf-8'))}|{on_reference_value.decode('utf-8')}"
        else:
            return on_reference_value.decode('utf-8')

    def get_id(self, contents):
        i = contents.find('@')
        if i != -1:
            return contents[i + 1:]
        else:
            return "FIXED"

    def get_payload(self, contents):
        return 0

    def get_type(self, payload):
        if payload is None:
            return StringStoreWorker.TestEnum.NULL
        elif payload > 60:
            return StringStoreWorker.TestEnum.YES
        else:
            return StringStoreWorker.TestEnum.NO

    def requires_global_state(self, contents):
        return '|' in contents or '@' in contents

    @staticmethod
    def get_metadata_serializer():
        return METADATA()

    @staticmethod
    def strip_contents_id(s):
        i = s.find('@')
        if i == -1:
            return s
        else:
            return s[:i]

METADATA = Serializer()


class Serializer:
    def from_bytes(self, bytes):
        return bytes.decode('utf-8')

    def to_bytes(self, value):
        return bytes(value.encode('utf-8'))
```

Please note that Python does not have direct equivalent of Java's `ByteString` and `Optional`. I replaced them with Python's built-in types.