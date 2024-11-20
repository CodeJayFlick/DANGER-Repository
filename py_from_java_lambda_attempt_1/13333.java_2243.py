Here is the translation of the Java code into Python:

```Python
class PIC30ElfExtension:
    EM_DSPIC30F = 118

    P30F = 1 << 0
    P30FSMPS = 1 << 1
    P33F = 1 << 2
    P24F = 1 << 3
    P24H = 1 << 4
    P24FK = 1 << 5
    P33E = 1 << 6
    P24E = 1 << 7

    SHF_MEMORY = (1 << 18)
    SHF_UNUSED = (1 << 19)

    def __init__(self):
        pass

    def can_handle(self, elf_header: 'ElfHeader') -> bool:
        return elf_header.e_machine() == self.EM_DSPIC30F

    def get_data_type_suffix(self) -> str:
        return "_PIC30"

    def process_elf(self, elf_load_helper: 'ElfLoadHelper', task_monitor):
        pass  # TODO: Create mapped blocks

    def get_preferred_segment_address_space(self, elf_load_helper: 'ElfLoadHelper', elf_program_header) -> 'AddressSpace':
        language = elf_load_helper.get_program().get_language()
        if self.is_data_load(elf_program_header):
            return language.get_default_data_space()
        return language.get_default_space()

    def get_preferred_section_address_space(self, elf_load_helper: 'ElfLoadHelper', elf_section_header) -> 'AddressSpace':
        language = elf_load_helper.get_program().get_language()
        if self.is_data_load(elf_section_header):
            return language.get_default_data_space()
        return language.get_default_space()

    def get_adjusted_data_load_size(self, data_load_file_size: int) -> int:
        return data_load_file_size // 2

    def is_data_load(self, loadable: 'MemoryLoadable') -> bool:
        if isinstance(loadable, ElfSectionHeader):
            return not self.is_executable_section(loadable)
        elif isinstance(loadable, ElfProgramHeader):
            return not loadable.is_execute()
        else:
            raise ValueError("Invalid type")

    def is_debug_section(self, section: 'MemoryLoadable') -> bool:
        if isinstance(section, ElfSectionHeader):
            name = section.get_name_as_string()
            return name.startswith(".debug_") or ".comment" == name
        elif isinstance(section, ElfProgramHeader):
            raise ValueError("Invalid type")
        else:
            raise ValueError("Invalid type")

    def get_adjusted_load_size(self, elf_program_header: 'ElfProgramHeader') -> int:
        file_size = elf_program_header.get_file_size()
        return self.is_data_load(elf_program_header) and self.get_adjusted_data_load_size(file_size)

    def get_adjusted_memory_size(self, elf_program_header: 'ElfProgramHeader') -> int:
        raw_size = elf_program_header.get_memory_size()
        return self.is_data_load(elf_program_header) and self.get_adjusted_data_load_size(raw_size)

    def get_filtered_load_input_stream(self, elf_load_helper: 'ElfLoadHelper', loadable: 'MemoryLoadable', start: 'Address', data_length: int, input_stream):
        language = elf_load_helper.get_program().get_language()
        if not self.is_data_load(loadable) and language.get_default_data_space() != start.get_address_space().get_physical_space():
            return input_stream
        elif isinstance(loadable, ElfSectionHeader):
            section = loadable
            if not elf_load_helper.get_elf_header().is_relocatable() and (section.get_flags() & self.SHF_PSV) != 0:
                # TODO: this is really mapped into ROM space where PT_LOAD was done to physical memory
                return PIC30FilteredPSVDataInputStream(input_stream)
        elif isinstance(loadable, ElfProgramHeader):
            if not elf_load_helper.get_elf_header().is_relocatable() and (loadable.get_flags() & self.SHF_PSV) != 0:
                # TODO: this is really mapped into ROM space where PT_LOAD was done to physical memory
                return PIC30FilteredPSVDataInputStream(input_stream)
        else:
            raise ValueError("Invalid type")

    def has_filtered_load_input_stream(self, elf_load_helper: 'ElfLoadHelper', loadable: 'MemoryLoadable', start):
        if loadable is None:
            return False
        elif self.is_data_load(loadable):
            return True
        language = elf_load_helper.get_program().get_language()
        return language.get_default_data_space() == start.get_address_space().get_physical_space()

    def get_default_alignment(self, elf_load_helper: 'ElfLoadHelper') -> int:
        return 4

class PIC30FilteredDataInputStream:
    pad_byte_toggle = False
    pos = 0
    check_padding = True

    def __init__(self, input_stream):
        super().__init__(input_stream)
        self.pad_byte_toggle = False
        self.pos = 0
        self.check_padding = True

    def read_next_byte(self) -> int:
        r = self.input_stream.read()
        if self.check_padding and self.pad_byte_toggle and r != 0:
            raise IOException("expected Data padding byte, pos=" + str(self.pos))
        self.pos += 1
        self.pad_byte_toggle = not self.pad_byte_toggle
        return r

    def read(self) -> int:
        while self.pad_byte_toggle:
            r = self.read_next_byte()
            if r < 0:
                return r
        return self.read_next_byte()

class PIC30FilteredPSVDataInputStream(PIC30FilteredDataInputStream):
    first_byte_toggle = True

    def __init__(self, input_stream):
        super().__init__(input_stream)
        self.first_byte_toggle = True

    def read_next_byte(self) -> int:
        r = self.input_stream.read()
        self.pos += 1
        if not self.first_byte_toggle:
            self.pad_byte_toggle = not self.pad_byte_toggle
        self.first_byte_toggle = not self.first_byte_toggle
        return r
```

Please note that this is a direct translation of the Java code into Python, and it may not be perfect. The original Java code has many TODO comments which indicate areas where you might need to add more functionality or handle certain cases differently in your Python implementation.