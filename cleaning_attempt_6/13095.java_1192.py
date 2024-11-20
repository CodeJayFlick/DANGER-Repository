class AARCH64_ElfExtension:
    # Elf Program Header Extensions
    PT_AARCH64_ARCHEXT = (0x70000000, "PT_AARCH64_ARCHEXT", "AARCH64 extension")

    # Elf Section Header Extensions
    SHT_AARCH64_ATTRIBUTES = (0x70000003, "SHT_AARCH64_ATTRIBUTES", "Attribute section")

    SHF_ENTRYSECT = 0x10000000  # section contains entry point
    SHF_COMDEF = 0x80000000  # section may be multiply defined

    def can_handle(self, elf):
        return elf.e_machine == 'EM_AARCH64'

    def can_handle_load_helper(self, load_helper):
        language = load_helper.get_program().get_language()
        return self.can_handle(load_helper.get_elf_header()) and "AARCH64" in str(language.get_processor())

    def get_data_type_suffix(self):
        return "_AARCH64"

    def evaluate_elf_symbol(self, load_helper, elf_symbol, address, is_external):
        if is_external:
            return address

        sym_name = elf_symbol.name_as_string
        if "$x".lower() == sym_name.lower() or sym_name.startswith("$x."):
            load_helper.mark_as_code(address)
            # do not retain $x symbols in program due to potential function/thunk naming interference
            load_helper.set_elf_symbol_address(elf_symbol, address)
            return None

        elif "$d".lower() == sym_name.lower() or sym_name.startswith("$d."):
            # is data, need to protect as data
            load_helper.create.undefined_data(address, elf_symbol.size)

            # do not retain $x symbols in program due to excessive duplicate symbols
            load_helper.set_elf_symbol_address(elf_symbol, address)
            return None

        return address


# Example usage:
aarch64_extension = AARCH64_ElfExtension()
load_helper = ...  # Your LoadHelper object
elf_header = ...  # Your ElfHeader object
address = ...  # Your Address object
is_external = True  # Whether the symbol is external or not

result = aarch64_extension.evaluate_elf_symbol(load_helper, elf_symbol, address, is_external)
print(result)  # Output: The evaluated result of the ELF symbol.
