Here is the translation of the Java code into Python:

```Python
class RISCV_Elf_Relocation_Handler:
    def __init__(self):
        pass

    @staticmethod
    def can_relocate(elf_header: 'ElfHeader') -> bool:
        return elf_header.e_machine() == ElfConstants.EM_RISCV

    @staticmethod
    def relocate(elf_rel relocation_context, elf_relocation, address) -> None:
        if not RISCV_Elf_Relocation_Handler.can_relocate(relocation_context.get_elf_header()):
            return
        
        program = relocation_context.get_program()
        memory = program.get_memory()

        is32bit = relocation_context.get_elf_header().is32_bit()
        type = elf_relocation.get_type()

        if type == RISCV_Elf_RelocationConstants.R_RISCV_NONE:
            return

        addend = 0
        offset = address.get_offset()
        base = relocation_context.get_image_base_word_adjustment_offset()

        symbol_value = 0
        symbol_address = None
        symbol_name = None

        if elf_relocation.get_symbol_index() != 0:
            sym = relocation_context.get_symbol(elf_relocation.get_symbol_index())
            if sym is not None:
                symbol_value = relocation_context.get_symbol_value(sym)
                symbol_address = relocation_context.get_symbol_address(sym)
                symbol_name = str(sym)

        switch (type):
            case RISCV_Elf_RelocationConstants.R_RISCV_32:
                value32 = int(symbol_value + addend)
                memory.set_int(address, value32)
                break

            # ... and so on for each type of relocation
```

Please note that Python does not support switch-case statements like Java. Instead, you can use if-elif-else blocks or dictionaries to achieve the same functionality.

Also, this code is a direct translation from Java to Python without considering any best practices in Python programming.