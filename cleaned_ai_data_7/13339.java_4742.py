class PowerPC64ElfExtension:
    PLT_ENTRY_SIZE = 8
    PLT_HEAD_SIZE = 16

    DT_PP_C64_GLINK = ElfDynamicType(0x70000000, "DT_PP_C64_GLINK", "Specify the start of the .glink section", ElfDynamicValueType.ADDRESS)
    DT_PP_C64_OPD = ElfDynamicType(0x70000001, "DT_PP_C64_OPD", "Specify the start of the .opd section", ElfDynamicValueType.ADDRESS)
    DT_PP_C64_OPDSZ = ElfDynamicType(0x70000002, "DT_PP_C64_OPDSZ", "Specify the size of the .opd section", ElfDynamicValueType.ADDRESS)
    DT_PP_C64_OPT = ElfDynamicType(0x70000003, "DT_PP_C64_OPT", "Specify whether various optimisations are possible", ElfDynamicValueType.VALUE)

    EF_PP_C64_ABI = 3

    TOC_BASE = "TOC_BASE"

    def __init__(self):
        pass

    def can_handle(self, elf_header: 'ElfHeader') -> bool:
        return elf_header.e_machine() == ElfConstants.EM_PPC64 and elf_header.is_64_bit()

    def get_data_type_suffix(self) -> str:
        return "_PPC64"

    def process_elf(self, elf_load_helper: 'ElfLoadHelper', monitor: TaskMonitor):
        if not self.can_handle(elf_load_helper.get_elf_header()):
            return

        self.find_toc_base(elf_load_helper, monitor)

    def find_toc_base(self, elf_load_helper: 'ElfLoadHelper', monitor: TaskMonitor):
        program = elf_load_helper.get_program()
        toc_addr = None
        got_block = program.memory.block(".got")
        if got_block is not None:
            toc_addr = got_block.start.add_no_wrap(0x8000)
        else:
            toc_block = program.memory.block(".toc")
            if toc_block is not None:
                toc_addr = toc_block.start

        if toc_addr is not None:
            elf_load_helper.create_symbol(toc_addr, self.TOC_BASE, False, False, None)

    def process_got_plt(self, elf_load_helper: 'ElfLoadHelper', monitor: TaskMonitor):
        if not self.can_handle(elf_load_helper.get_elf_header()):
            return

        set_entry_point_context(elf_load_helper, monitor)
        self.process_opd_section(elf_load_helper, monitor)

    def process_ppc64_plt_pointer_table(self, elf_load_helper: 'ElfLoadHelper', monitor: TaskMonitor):
        if not self.can_handle(elf_load_helper.get_elf_header()):
            return

        plt_block = elf_load_helper.get_program().memory.block(".plt")
        if plt_block is None:
            return

    def process_opd_section(self, elf_load_helper: 'ElfLoadHelper', monitor: TaskMonitor):
        opd_block = elf_load_helper.get_program().memory.block(".opd")
        if opd_block is None:
            return

        for addr in range(opd_block.start, opd_block.end + 1):
            self.process_opd_entry(elf_load_helper, addr)

    def process_ppc64v2_plt_pointer_table(self, elf_load_helper: 'ElfLoadHelper', monitor: TaskMonitor):
        if not self.can_handle(elf_load_helper.get_elf_header()):
            return

        plt_block = elf_load_helper.get_program().memory.block(".plt")
        if plt_block is None:
            return

    def process_opd_entry(self, elf_load_helper: 'ElfLoadHelper', opd_addr: Address):
        program = elf_load_helper.get_program()
        symbol_table = program.symbol_table
        ref_symbol = self.markup_descriptor_entry(elf_load_helper, opd_addr)
        if ref_symbol is None:
            return

    def markup_descriptor_entry(self, elf_load_helper: 'ElfLoadHelper', entry_addr: Address) -> Symbol:
        # ... rest of the code ...

    def set_entry_point_context(self, elf_load_helper: 'ElfLoadHelper', monitor: TaskMonitor):
        program = elf_load_helper.get_program()
        if self.get_ppc64_abi_version(elf_load_helper.get_elf_header()) == 2:
            for addr in range(program.memory.block(".plt").start, program.memory.block(".plt").end + 1):
                self.set_ppc64v2_global_function_r12_context(program, addr)

    def set_ppc64v2_global_function_r12_context(self, program: 'Program', function_addr: Address):
        # ... rest of the code ...

    def get_ppc64_abi_version(self, elf_header: 'ElfHeader') -> int:
        if elf_header.e_machine() != ElfConstants.EM_PPC64:
            return 0
        return elf_header.e_flags() & self.EF_PP_C64_ABI

class Address:
    pass

class Program:
    def __init__(self):
        pass

    @property
    def memory(self) -> 'Memory':
        return Memory()

    @property
    def symbol_table(self) -> SymbolTable:
        return SymbolTable()
