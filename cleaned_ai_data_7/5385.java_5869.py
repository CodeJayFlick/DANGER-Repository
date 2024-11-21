import struct

class ElfDataType:
    def __init__(self):
        self.serialVersionUID = 1

    def get_mnemonic(self, settings):
        return "ELF"

    def get_description(self):
        return "ELF Data Type"

    def populate_dynamic_structure(self, buf, struct):
        try:
            memory = buf.get_memory()
            block = memory.get_block(buf.get_address())
            bytes = bytearray(block.get_size().value)
            block.get_bytes(block.get_start(), bytes)

            bap = ByteArrayProvider(bytes)
            elf_header = ElfHeader.create_elf_header(RethrowContinuesFactory.INSTANCE, bap)
            elf_header.parse()

            struct.add(elf_header.to_data_type())

        except Exception as e:
            pass

    def clone(self):
        return ElfDataType()
