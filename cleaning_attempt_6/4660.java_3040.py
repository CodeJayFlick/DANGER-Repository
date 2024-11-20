class DWARFCompilationUnit:
    def __init__(self, dwarf_program: 'DWARFProgram', start_offset: int, end_offset: int,
                 length: int, format: int, version: int, abbreviation_offset: int, pointer_size: bytes,
                 comp_unit_number: int, first_die_offset: int, code_to_abbreviation_map: dict):
        self.dwarf_program = dwarf_program
        self.start_offset = start_offset
        self.end_offset = end_offset
        self.length = length
        self.format = format
        self.version = version
        self.abbreviation_offset = abbreviation_offset
        self.pointer_size = pointer_size
        self.comp_unit_number = comp_unit_number
        self.first_die_offset = first_die_offset
        if code_to_abbreviation_map is None:
            self.code_to_abbreviation_map = {}
        else:
            self.code_to_abbreviation_map = code_to_abbreviation_map

    @property
    def compile_unit(self):
        return self._comp_unit

    @compile_unit.setter
    def compile_unit(self, value: 'DWARFCompileUnit'):
        self._comp_unit = value

    @property
    def program(self):
        return self.dwarf_program

    @property
    def length(self):
        return self.length

    @property
    def pointer_size(self):
        return self.pointer_size

    @property
    def start_offset(self):
        return self.start_offset

    @property
    def end_offset(self):
        return self.end_offset

    @property
    def format(self):
        return self.format

    def contains_offset(self, offset: int) -> bool:
        return self.first_die_offset <= offset < self.end_offset

    def __str__(self):
        buffer = f"Compilation Unit [Start:0x{self.start_offset:x}]"
        buffer += f"[Length:0x{self.length:x}]"
        buffer += f"[AbbreviationOffset:0x{self.abbreviation_offset:x}]"
        if self.compile_unit is not None:
            buffer += f"[CompileUnit:{self.compile_unit.__str__()}]"
        return buffer

    def get_code_to_abbreviation_map(self):
        return self.code_to_abbreviation_map

    def get_first_die_offset(self) -> int:
        return self.first_die_offset

    def get_comp_unit_number(self) -> int:
        return self.comp_unit_number


class DWARFCompileUnit:
    pass  # This class is not implemented in the given Java code.


def read_compilation_unit(dwarf_program: 'DWARFProgram', debug_info_br, debug_abbr_br,
                          comp_unit_number: int, monitor) -> 'DWARFCompilationUnit':
    start_offset = debug_info_br.get_pointer_index()
    length_result = DWARFUtil.read_length(debug_info_br, dwarf_program.ghidra_program)
    if length_result.length == 0:
        if is_all_zeros_until_eof(debug_info_br):
            return None
        else:
            raise DWARFException("Invalid DWARF length 0 at 0x" + str(long(start_offset)))

    end_offset = debug_info_br.get_pointer_index() + length_result.length
    version = debug_info_br.read_next_short()
    abbreviation_offset = DWARFUtil.read_offset_by_dwarf_format(debug_info_br, length_result.format)
    pointer_size = debug_info_br.read_next_byte()
    first_die_offset = debug_info_br.get_pointer_index()

    if version < 2 or version > 4:
        raise DWARFException("Only DWARF version 2, 3, or 4 information is currently supported.")
    if first_die_offset > end_offset:
        raise IOException("Invalid length " + str(end_offset - start_offset) +
                           " for DWARF Compilation Unit at 0x" + str(long(start_offset)))

    debug_abbr_br.set_pointer_index(abbreviation_offset)
    abbr_map = DWARFAbbreviation.read_abbreviations(debug_abbr_br, dwarf_program, monitor)

    cu = DWARFCompilationUnit(dwarf_program, start_offset, end_offset,
                               length_result.length, length_result.format, version,
                               abbreviation_offset, pointer_size, comp_unit_number,
                               first_die_offset, abbr_map)
    try:
        compile_unit_die = DebugInfoEntry.read(debug_info_br, cu, dwarf_program.attribute_factory)
        comp_unit = DWARFCompileUnit.read(DIEAggregate.create_single(compile_unit_die))
        cu.compile_unit = comp_unit
        return cu
    except IOException as ioe:
        Msg.error(None,
                   "Failed to parse the DW_ TAG_compile_unit DIE at the start of compilation unit "
                   + str(comp_unit_number) +
                   " at offset 0x" + str(long(start_offset)) + ", skipping entire compilation unit",
                   ioe)
        debug_info_br.set_pointer_index(cu.get_end_offset())
        return None


def is_all_zeros_until_eof(reader):
    reader = reader.clone()
    while reader.get_pointer_index() < reader.length:
        if reader.read_next_byte() != 0:
            return False
    return True
