Here is the translation of the Java code into Python:

```Python
class AARCH64_ElfRelocationHandler:
    def __init__(self):
        pass

    def can_relocate(self, elf_header: ElfHeader) -> bool:
        return elf_header.e_machine() == ElfConstants.EM_AARCH64

    def get_relr_relocation_type(self) -> int:
        return AARCH64_ElfRelocationConstants.R_AARCH64_RELATIVE

    def relocate(self, elf_relocation_context: ElfRelocationContext, relocation: ElfRelocation,
                 address: Address):
        if not self.can_relocate(elf_relocation_context.get_elf_header()):
            return
        program = elf_relocation_context.get_program()
        memory = program.get_memory()

        type = relocation.get_type()
        symbol_index = relocation.get_symbol_index()

        addend = relocation.get_addend()  # will be 0 for REL case

        if type == AARCH64_ElfRelocationConstants.R_AARCH64_ABS64:
            sym = elf_relocation_context.get_symbol(symbol_index)
            symbol_name = sym.name_as_string()
            offset = address.offset
            is_big_endian_instructions = program.language_description().instruction_endianness.is_big_endian()

            symbol_addr = elf_relocation_context.symbol_address(sym)
            symbol_value = elf_relocation_context.symbol_value(sym)

            if addend != 0 and self.is_unsupported_external_relocation(program, relocation.address,
                                                                        symbol_addr, symbol_name, addend):
                addend = 0
            new_value = (symbol_value + addend)
            memory.set_long(address, new_value)

        elif type == AARCH64_ElfRelocationConstants.R_AARCH64_ABS32:
            sym = elf_relocation_context.get_symbol(symbol_index)
            symbol_name = sym.name_as_string()
            offset = address.offset
            is_big_endian_instructions = program.language_description().instruction_endianness.is_big_endian()

            symbol_addr = elf_relocation_context.symbol_address(sym)
            symbol_value = elf_relocation_context.symbol_value(sym)

            new_value = (symbol_value + addend)
            memory.set_int(address, int((new_value & 0xffffffff)))

        elif type == AARCH64_ElfRelocationConstants.R_AARCH64_ABS16:
            sym = elf_relocation_context.get_symbol(symbol_index)
            symbol_name = sym.name_as_string()
            offset = address.offset
            is_big_endian_instructions = program.language_description().instruction_endianness.is_big_endian()

            symbol_addr = elf_relocation_context.symbol_address(sym)
            symbol_value = elf_relocation_context.symbol_value(sym)

            new_value = (symbol_value + addend)
            memory.set_short(address, int((new_value & 0xffff)))

        elif type == AARCH64_ElfRelocationConstants.R_AARCH64_PREL64:
            sym = elf_relocation_context.get_symbol(symbol_index)
            symbol_name = sym.name_as_string()
            offset = address.offset
            is_big_endian_instructions = program.language_description().instruction_endianness.is_big_endian()

            symbol_addr = elf_relation