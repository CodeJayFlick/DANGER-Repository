Here is the translation of the given Java code into equivalent Python:

```Python
class FBPT_Entry:
    def __init__(self, reader, is_last):
        self.is_last = is_last
        self.name = reader.read_ascii_string(FBPK_Constants.NAME_MAX_LENGTH)
        if FBPK_Constants.LAST_PARTITION_ENTRY == self.name:
            return

        self.guid1 = reader.read_ascii_string(FBPK_Constants.NAME_MAX_LENGTH + 1)
        self.guid2 = reader.read_ascii_string(FBPK_Constants.NAME_MAX_LENGTH + 1)
        self.padding = reader.read_ascii_string(2)

        if not is_last:
            self.unknown1 = reader.read_int()
            self.unknown2 = reader.read_int()
            self.unknown3 = reader.read_int()

    def get_name(self):
        return self.name

    def get_guid1(self):
        return self.guid1

    def get_guid2(self):
        return self.guid2

    def get_padding(self):
        return self.padding

    def get_unknown1(self):
        return self.unknown1

    def get_unknown2(self):
        return self.unknown2

    def get_unknown3(self):
        return self.unknown3


class FBPT_EntryConverter:
    @staticmethod
    def to_data_type(self) -> dict:
        data_type = {
            "name": {"type": "string", "length": FBPK_Constants.NAME_MAX_LENGTH},
            "guid1": {"type": "string", "length": FBPK_Constants.NAME_MAX_LENGTH + 1},
            "guid2": {"type": "string", "length": FBPK_Constants.NAME_MAX_LENGTH + 1},
            "padding": {"type": "string", "length": 2}
        }

        if FBPK_Constants.LAST_PARTITION_ENTRY == self.name or self.is_last:
            data_type["name"]["is_last"] = True
        else:
            data_type.update({
                "unknown1": {"type": "int"},
                "unknown2": {"type": "int"} if not self.is_last else {},
                "unknown3": {"type": "int"} if not self.is_last else {}
            })

        return data_type

# Assuming FBPK_Constants and read_ascii_string are defined elsewhere
FBPT_EntryConverter = FBPT_EntryConverter()
```

Please note that this is a direct translation of the given Java code into equivalent Python.