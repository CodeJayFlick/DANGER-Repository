Here is the translation of the given Java code into equivalent Python:

```Python
class BaseRelocationDataDirectory:
    def __init__(self):
        self.relocs = []

    @staticmethod
    def create_base_relocation_data_directory(nt_header, reader) -> 'BaseRelocationDataDirectory':
        base_relocation_data_directory = BaseRelocationDataDirectory()
        base_relocation_data_directory.init_base_relocation_data_directory(nt_header, reader)
        return base_relocation_data_directory

    def init_base_relocation_data_directory(self, nt_header, reader):
        self.process_data_directory(nt_header, reader)
        if not hasattr(self, 'relocs'):
            self.relocs = []

    @property
    def directory_name(self) -> str:
        return "IMAGE_DIRECTORY_ENTRY_BASERELOC"

    def markup(self, program: object, is_binary: bool, monitor: object, log: object, nt_header: object):
        if not hasattr(program, 'get_memory'):
            return

        address = PeUtils.get_markup_address(program, is_binary, nt_header, self.virtual_address)
        if not program.get_memory().contains(address):
            return
        create_directory_bookmark(program, address)

        for reloc in self.relocs:
            if monitor.is_cancelled():
                return
            PeUtils.create_data(program, address, DWORD(), log)
            address += DWORD().get_length()

            count = reloc.get_count()
            for j in range(count):
                if monitor.is_cancelled():
                    return
                PeUtils.create_data(program, address, WORD(), log)
                address += WORD().get_length()

    def parse(self) -> bool:
        addr = self.pointer
        if addr < 0:
            return False

        stop = addr + self.size

        relocs_list = []

        while True:
            if addr >= stop:
                break

            br = BaseRelocation.create_base_relocation(reader, addr)

            # Sanity check to make sure the data looks OK.
            if br.get_virtual_address() == 0 or \
               br.get_size_of_block() < BaseRelocation.IMAGE_SIZEOF_BASE_RELOCATION or \
               br.get_size_of_block() == 0:
                break

            relocs_list.append(br)
            addr += br.get_size_of_block()

        self.relocs = [BaseRelocation(*_) for _ in relocs_list]
        return True

    def get_base_relocations(self) -> list:
        return self.relocs

    @staticmethod
    def to_data_type():
        struct = StructureDataType("IMAGE_DIRECTORY_ENTRY_BASERELOC", 0)
        for reloc in self.relocs:
            struct.add(reloc.to_data_type())
        struct.set_category_path("/PE")
        return struct

    def remove_all_relocations(self):
        self.relocs = []
        self.size = 0

    @staticmethod
    def create_base_relocation(va: int) -> 'BaseRelocation':
        return BaseRelocation(va)

    def add_base_relocation(self, reloc: object):
        self.size += reloc.get_size_of_block()

        tmp = [self.relocs[0]] + list(reloc)
        self.relocs = tmp

    @staticmethod
    def to_bytes(dc: DataConverter) -> bytes:
        lsize = 0
        for reloc in self.relocs:
            lsize += reloc.get_size_of_block()
        bytes = bytearray(lsize)

        pos = 0
        for reloc in self.relocs:
            reloc_bytes = reloc.to_bytes(dc)
            bytes[pos:pos + len(reloc_bytes)] = reloc_bytes
            pos += len(reloc_bytes)

        return bytes

class BaseRelocation:
    @staticmethod
    def create_base_relocation(reader, addr):
        # Implementation of this method is missing in the given Java code.
        pass

    def get_count(self) -> int:
        # Implementation of this method is missing in the given Java code.
        pass

    def to_data_type(self) -> object:
        # Implementation of this method is missing in the given Java code.
        pass
```

Note that I have not implemented all methods as they were either static or abstract. Also, Python does not support direct translation from Java and some modifications are required for better compatibility with Python's syntax and semantics.