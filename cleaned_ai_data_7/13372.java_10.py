class SPARC_Elf_Relocation_Handler:
    def can_relocate(self, elf):
        return (elf.e_machine() == 24 or 
                elf.e_machine() == 51 or 
                elf.e_machine() == 52)

    def relocate(self, elf_rel_context, relocation, address):
        if not self.can_relocate(elf_rel_context.get_elf_header()):
            return

        program = elf_rel_context.get_program()
        memory = program.get_memory()

        type = relocation.get_type()
        symbol_index = relocation.get_symbol_index()

        addend = relocation.get_addend()  # will be 0 for REL case
        offset = address.offset

        sym = elf_rel_context.get_symbol(symbol_index)
        if sym is not None:
            symbol_name = sym.name_as_string
        else:
            symbol_name = None

        symbol_value = elf_rel_context.get_symbol_value(sym)

        old_val = memory.get_int(address)
        new_val = 0

        match type:
            case SPARC_Elf_RelocationConstants.R_SPARC_NONE:
                return
            case SPARC_Elf_RelocationConstants.R_SPARC_DISP32:
                new_val = (symbol_value + addend - offset)
                memory.set_int(address, old_val | new_val)
                break
            case SPARC_Elf_RelocationConstants.R_SPARC_WDISP30:
                new_val = (symbol_value + addend - offset) >> 2
                memory.set_int(address, old_val | new_val)
                break
            case SPARC_Elf_RelocationConstants.R_SPARC_HI22:
                new_val = ((symbol_value << 10) + addend) >> 10
                memory.set_int(address, old_val | new_val)
                break
            case SPARC_Elf_RelocationConstants.R_SPARC_LO10:
                new_val = ((symbol_value << 10) + addend) & 0x3FF
                memory.set_int(address, old_val | new_val)
                break
            case SPARC_Elf_RelocationConstants.R_SPARC_JMP_SLOT: 
                # should copy address of symbol in EXTERNAL block
            case SPARC_Elf_RelocationConstants.R_SPARC_32:
                new_val = (symbol_value + addend)
                memory.set_int(address, new_val)
                break
            case SPARC_Elf_RelocationConstants.R_SPARC_GLOB_DAT:
                new_val = symbol_value
                memory.set_int(address, new_val)
                break
            case SPARC_Elf_RelocationConstants.R_SPARC_RELATIVE:
                new_val = elf_rel_context.get_elf_header().get_image_base() + addend
                memory.set_int(address, new_val)
                break
            case SPARC_Elf_RelocationConstants.R_SPARC_UA32:
                new_val = (symbol_value + addend)
                memory.set_int(address, new_val)
                break
            case SPARC_Elf_RelocationConstants.R_SPARC_COPY:
                self.mark_as_warning(program, address, "R_SPARC_COPY", symbol_name, 
                                      symbol_index, "Runtime copy not supported", elf_rel_context.get_log())
                break
            default:
                self.mark_as_unhandled(program, address, type, symbol_index, symbol_name,
                                       elf_rel_context.get_log())
                break

class ElfRelocationContext:
    def __init__(self):
        pass

    def get_elf_header(self):
        return None  # Replace with actual implementation

    def get_program(self):
        return None  # Replace with actual implementation

    def get_memory(self):
        return None  # Replace with actual implementation

    def get_symbol(self, index):
        return None  # Replace with actual implementation

    def get_symbol_value(self, sym):
        return None  # Replace with actual implementation

    def mark_as_warning(self, program, address, relocation_type, symbol_name, 
                         symbol_index, message, log):
        pass  # Replace with actual implementation

    def mark_as_unhandled(self, program, address, type, symbol_index, symbol_name, log):
        pass  # Replace with actual implementation
