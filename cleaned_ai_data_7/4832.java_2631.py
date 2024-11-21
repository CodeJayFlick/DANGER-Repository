class MachoRelocation:
    def __init__(self, program: 'Program', macho_header: 'MachoHeader', relocation_address: int, 
                 relocation_info: 'RelocationInfo'):
        self.program = program
        self.space = program.get_address_space()
        self.macho_header = macho_header
        self.relocation_address = relocation_address
        self.relocation_info = relocation_info

        if relocation_info.is_scattered():
            self.target_pointer = space.get_address(relocation_info.get_value())
        elif relocation_info.is_external():
            self.target_symbol = find_target_symbol(program, relocation_info)
        else:
            self.target_section = find_target_section(macho_header, relocation_info)

    def __init__(self, program: 'Program', macho_header: 'MachoHeader', relocation_address: int, 
                 relocation_info: 'RelocationInfo', relocation_info_extra: 'RelocationInfo'):
        super().__init__(program, macho_header, relocation_address, relocation_info)
        self.relocation_info_extra = relocation_info_extra

        if relocation_info_extra.is_scattered():
            self.target_pointer_extra = space.get_address(relocation_info_extra.get_value())
        elif relocation_info_extra.is_external():
            self.target_symbol_extra = find_target_symbol(program, relocation_info_extra)
        else:
            self.target_section_extra = find_target_section(macho_header, relocation_info_extra)

    def get_program(self):
        return self.program

    def get_relocation_address(self):
        return self.relocation_address

    def get_relocation_info(self):
        return self.relocation_info

    def get_relocation_info_extra(self):
        return self.relocation_info_extra

    def get_target_address(self) -> int:
        if self.target_symbol is not None:
            return self.target_symbol.get_address()
        elif self.target_section is not None:
            return space.get_address(self.target_section.get_address())
        elif self.target_pointer is not None:
            return self.target_pointer
        else:
            raise NotFoundException("Relocation target not found")

    def get_target_address_extra(self) -> int:
        if self.target_symbol_extra is not None:
            return self.target_symbol_extra.get_address()
        elif self.target_section_extra is not None:
            return space.get_address(self.target_section_extra.get_address())
        elif self.target_pointer_extra is not None:
            return self.target_pointer_extra
        else:
            raise NotFoundException("Extra relocation target not found")

    def requires_relocation(self) -> bool:
        if (self.relocation_info.is_external() and 
           not self.relocation_info.is_scattered()):
            return True

        if self.relocation_info_extra is not None:
            if (relocation_info_extra.is_external() and 
               not relocation_info_extra.is_scattered()):
                return True
        return False

    def get_target_description(self) -> str:
        sb = StringBuilder()

        if self.target_pointer is not None:
            sb.append(str(self.target_pointer))
        elif self.target_symbol is not None:
            sb.append(self.target_symbol.get_name())
        elif self.target_section is not None:
            sb.append(self.target_section.get_section_name())

        else:
            sb.append(NumericUtilities.to_hex_string(relocation_info.get_value()))

        if relocation_info_extra is not None:
            sb.append(" / ")
            if self.target_pointer_extra is not None:
                sb.append(str(self.target_pointer_extra))
            elif self.target_symbol_extra is not None:
                sb.append(self.target_symbol_extra.get_name())
            elif self.target_section_extra is not None:
                sb.append(self.target_section_extra.get_section_name())

        return str(sb)

    def __str__(self) -> str:
        sb = StringBuilder()
        if self.target_symbol is not None and self.target_section is not None:
            sb.append(f"Symbol: {self.target_symbol}, Section: {self.target_section}\n")
        else:
            sb.append(str(self.relocation_info))
        if relocation_info_extra is not None:
            if self.target_symbol_extra is not None and self.target_section_extra is not None:
                sb.append(
                    f"Symbol: {self.target_symbol_extra}, Section: {self.target_section_extra}\n"
                )
            else:
                sb.append(str(relocation_info_extra))
        return str(sb)

    @staticmethod
    def find_target_symbol(program, reloc_info):
        sym = None
        nlist = macho_header.get_first_load_command(SymbolTableCommand).get_symbol_at(
            reloc_info.get_value()
        )
        addr = space.get_address(nlist.get_value())
        sym = program.get_symbol_table().get_symbol(
            SymbolUtilities.replace_invalid_chars(nlist.get_string(), True), addr, None
        )

        if sym is None:
            sym = SymbolUtilities.get_label_or_function_symbol(program, nlist.get_string())

        return sym

    @staticmethod
    def find_target_section(macho_header, reloc_info):
        index = reloc_info.get_value() - 1
        if index >= 0 and index < macho_header.get_all_sections().size():
            return macho_header.get_all_sections()[index]
        else:
            return None


class NotFoundException(Exception):
    pass

# Usage example:

program = Program()
macho_header = MachoHeader()

relocation_info = RelocationInfo()
relocation_info_extra = RelocationInfo()

relocation = MachoRelocation(program, macho_header, 0x10000000, relocation_info)
print(relocation.get_target_address())

try:
    print(relocation.get_target_address_extra())
except NotFoundException as e:
    print(f"Exception: {e}")
