class AVR32_ElfRelocationHandler:
    def __init__(self):
        pass

    @staticmethod
    def can_relocate(elf_header: ElfHeader) -> bool:
        return elf_header.e_machine() == ElfConstants.EM_AVR32

    @staticmethod
    def relocate(
            elf_relocation_context: ElfRelocationContext,
            relocation: ElfRelocation,
            relocation_address: Address
    ) -> None:
        program = elf_relation_context.get_program()
        memory = program.get_memory()

        type = relocation.type
        symbol_index = relocation.symbol_index

        addend = relocation.addend  # will be 0 for REL case

        elf_header = elf_relocation_context.get_elf_header()
        if (symbol_index == 0) and (elf_header.e_machine() == ElfConstants.EM_AVR32):
            pass
        elif symbol_index == 0:
            return

        offset = relocation_address.offset

        sym = elf_relation_context.get_symbol(symbol_index)
        symbol_value = elf_relocation_context.get_symbol_value(sym)

        old_value = memory.get_int(relocation_address)

        if elf_header.e_machine() == ElfConstants.EM_AVR32:
            new_value_shift_to_alignto_upper = 0
            match type:
                case AVR32_ElfRelocationConstants.R_AVRL_32:
                    new_value = ((symbol_value + addend) & 0xffffffff)
                    memory.set_int(relocation_address, new_value)
                case AVR32_ElfRelocationConstants.R_AVRL_DIFF32:
                    new_value = (((symbol_value + addend + old_value) & 0xffffffff))
                    memory.set_int(relocation_address, new_value)
                case AVR32_ElfRelocationConstants.R_AVRL_22H_PCREL:
                    new_value = ((symbol_value + addend - offset) >> 1)
                    nVpart1 = (new_value & 0x0000ffff)
                    nVpart2 = (new_value & 0x00010000)
                    nVpart3 = (new_value & 0x001e0000)
                    new_value_parts = (((nVpart3 << 8) | (nVpart2 << 4) | (nVpart1)) & 0x1e10ffff)
                    new_value_set = (old_value | new_value_parts)
                    memory.set_int(relocation_address, new_value_set)
                case AVR32_ElfRelocationConstants.R_AVRL_11H_PCREL:
                    new_value = ((symbol_value + addend - offset) >> 1) << 4
                    temp_new_val_hold = (new_value & 0x00000ff3)
                    temp_disp_hold = ((new_value & 0x00003000) >> 12)
                    new_value_shift_to_alignto_upper = ((temp_new_val_hold << 16) | (temp_disp_hold << 16))
                    new_value = ((old_value | new_value_shift_to_alignto_upper) & 0xffffffff)
                    memory.set_int(relocation_address, new_value)
                case AVR32_ElfRelocationConstants.R_AVRL_9H_PCREL:
                    new_value = (((symbol_value + addend - offset) >> 1) << 4) & 0x000007f0
                    new_value_shift_to_alignto_upper = (new_value << 16)
                    new_value = ((old_value | new_value_shift_to_alignto_upper) & 0xffffffff)
                    memory.set_int(relocation_address, new_value)
                case AVR32_ElfRelocationConstants.R_AVRL_9W_P:
                    new_value = (((symbol_value + addend - (offset & 0xfffffffc)) >> 2) << 4) & 0x000007f0
                    new_value_shift_to_alignto_upper = (new_value << 16)
                    new_value = ((old_value | new_value_shift_to_alignto_upper) & 0xffffffff)
                    memory.set_int(relocation_address, new_value)

        try:
            listing = program.get_listing()
            listing.create_data(relocation_address, StructConverter.POINTER, relocation_address.pointer_size())
        except CodeUnitInsertionException as cuie:
            print(f"Attempting to create Pointer Data: {cuie}")

    def mark_as_unhandled(self, program: Program, relocation_address: Address, type: int, symbol_index: int, symbol_name: str, log):
        pass
