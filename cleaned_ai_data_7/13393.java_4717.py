class X86_32_ElfExtension:
    def can_handle(self, elf):
        return (elf.e_machine() == 3) and elf.is_32bit()

    def can_handle_load_helper(self, elf_load_helper):
        language = elf_load_helper.get_program().get_language()
        return self.can_handle(elf_load_helper.get_elf_header()) and "x86" in str(language.get_processor()) and language.get_language_description().size == 32

    def get_data_type_suffix(self):
        return "_x86"

    def process_got_plt(self, elf_load_helper, monitor):
        if not self.can_handle(elf_load_helper):
            return
        super.process_got_plt(elf_load_helper, monitor)
        self.process_x86_plt(elf_load_helper, monitor)

    def process_x86_plt(self, elf_load_helper, monitor):
        # TODO: Does 64-bit have a similar mechanism?
        # TODO: Would be better to use only dynamic table entries since sections may be stripped
        # the unresolved issue is to determine the length of the PLT area without a section

        elf_header = elf_load_helper.get_elf_header()
        plt_section = elf_header.get_section_by_name(".plt")
        if plt_section is None or not plt_section.is_executable():
            return

        dynamic_table = elf_header.get_dynamic_table()
        if dynamic_table is None or not dynamic_table.contains_value(3):
            return  # avoid NotFoundException which causes issues for importer
        program = elf_load_helper.get_program()
        memory = program.get_memory()

        plt_block = memory.get_block_by_name(".plt")
        if plt_block is None:
            return

        try:
            pltgot_offset = elf_header.adjust_address_for_prelink(dynamic_table.get_value(3))
            pltgot_offset = elf_load_helper.default_address(pltgot_offset).get_offset()  # adjusted for image base
            pltgot_value = RegisterValue(Register("EBX"), BigInteger(str(pltgot_offset)))
            program.program_context.set_register_value(plt_block.start, plt_block.end, pltgot_value)
        except (NotFoundException, ContextChangeException) as e:
            raise AssertionError("unexpected", e)

class RegisterValue:
    def __init__(self, register, value):
        self.register = register
        self.value = value

class ProgramContext:
    def set_register_value(self, start, end, value):
        pass  # implementation left out for brevity

# usage example
x86_32_elf_extension = X86_32_ElfExtension()
