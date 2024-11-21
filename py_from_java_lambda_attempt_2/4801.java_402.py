Here is the translation of the given Java code into Python:

```Python
import io
from ghidra_app_util_bin_format_macho_commands import LoadCommand


class UuidCommand(LoadCommand):
    def __init__(self):
        self.uuid = None

    @staticmethod
    def create_uuid_command(reader):
        command = reader.get_factory().create(UuidCommand)
        command.init_uuid_command(reader)
        return command

    def init_uuid_command(self, reader):
        super().init_load_command(reader)
        self.uuid = reader.read_next_byte_array(16)

    def get_uuid(self):
        return self.uuid


class MachConstants:
    DATA_TYPE_CATEGORY = None
```

Note that the `MachConstants` class is not a part of the original Java code, but it seems to be used in the Python translation as well.