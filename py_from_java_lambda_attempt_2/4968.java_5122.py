Here is the translation of the given Java code into Python:

```Python
class ArchitectureDataDirectory:
    NAME = "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE"

    def __init__(self):
        pass

    @staticmethod
    def create_architecture_data_directory(nt_header, reader) -> 'ArchitectureDataDirectory':
        architecture_data_directory = ArchitectureDataDirectory()
        architecture_data_directory.init_architecture_data_directory(nt_header, reader)
        return architecture_data_directory

    def init_architecture_data_directory(self, nt_header, reader):
        self.process_data_directory(nt_header, reader)

    @property
    def get_directory_name(self) -> str:
        return self.NAME

    def markup(self, program: 'Program', is_binary: bool, monitor: 'TaskMonitor', log: 'MessageLog',
               nt_header: 'NTHeader') -> None:
        if not program.get_memory().contains(PeUtils.get_markup_address(program, is_binary, nt_header, self.virtual_address)):
            return
        self.create_directory_bookmark(program, PeUtils.get_markup_address(program, is_binary, nt_header, self.virtual_address))
        PeUtils.create_data(program, PeUtils.get_markup_address(program, is_binary, nt_header, self.virtual_address), self.to_data_type(), log)

    def parse(self) -> bool:
        ptr = self.get_pointer()
        if ptr < 0:
            return False
        if self.size > 1000:
            Msg.info(self, f"Requesting ASCII string of size {self.size}")
            return False
        self.copyright = reader.read_ascii_string(ptr, self.size)
        return True

    @property
    def get_copyright(self) -> str:
        return self.copyright

    def to_data_type(self) -> 'DataType':
        struct = StructureDataType(self.NAME, 0)
        if self.size > 0:
            struct.add(StringDataType(), self.size, "Copyright", None)
        struct.set_category_path(CategoryPath("/PE"))
        return struct
```

Note: This is a direct translation of the given Java code into Python. It may not be perfect and might require some adjustments to work correctly in your specific use case.