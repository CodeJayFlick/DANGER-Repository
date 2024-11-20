class AbstractModuleInformation:
    def __init__(self):
        pass

    @property
    def module_pointer(self):
        return self._module_pointer

    @module_pointer.setter
    def module_pointer(self, value):
        self._module_pointer = value

    @property
    def section_contribution(self):
        return self._section_contribution

    @section_contribution.setter
    def section_contribution(self, value):
        self._section_contribution = value

    @property
    def written_since_open(self):
        return self._written_since_open

    @written_since_open.setter
    def written_since_open(self, value):
        self._written_since_open = value

    @property
    def ec_symbolic_information_enabled(self):
        return self._ec_symbolic_information_enabled

    @ec_symbolic_information_enabled.setter
    def ec_symbolic_information_enabled(self, value):
        self._ec_symbolic_information_enabled = value

    @property
    def bitfield(self):
        return self._bitfield

    @bitfield.setter
    def bitfield(self, value):
        self._bitfield = value

    @property
    def spare(self):
        return self._spare

    @spare.setter
    def spare(self, value):
        self._spare = value

    @property
    def index_to_tsm_list(self):
        return self._index_to_tsm_list

    @index_to_tsm_list.setter
    def index_to_tsm_list(self, value):
        self._index_to_tsm_list = value

    @property
    def stream_number_debug_information(self):
        return self._stream_number_debug_information

    @stream_number_debug_information.setter
    def stream_number_debug_information(self, value):
        self._stream_number_debug_information = value

    @property
    def size_local_symbols_debug_information(self):
        return self._size_local_symbols_debug_information

    @size_local_symbols_debug_INFORMATION.setter
    def size_local_symbols_debug_INFORMATION(self, value):
        self._size_local_symbols_debug_INFORMATION = value

    @property
    def size_line_number_debug_information(self):
        return self._size_line_number_debug_information

    @size_line_number_debug_INFORMATION.setter
    def size_line_number_debug_INFORMATION(self, value):
        self._size_line_number_debug_INFORMATION = value

    @property
    def size_c13_style_line_number_information(self):
        return self._size_c13_style_line_number_information

    @size_c13_style_line_NUMBER_INFORMATION.setter
    def size_c13_style_LINE_NUMBER_INFORMATION(self, value):
        self._size_c13_style_LINE_NUMBER_INFORMATION = value

    @property
    def num_files_contributing(self):
        return self._num_files_contributing

    @num_files_contributing.setter
    def num_files_contributing(self, value):
        self._num_files_contributing = value

    @property
    def offsets_array(self):
        return self._offsets_array

    @offsets_array.setter
    def offsets_array(self, value):
        self._offsets_array = value

    @property
    def filenames_array(self):
        return self._filenames_array

    @filenames_array.setter
    def filenames_array(self, value):
        self._filenames_array = value

    @property
    def module_name(self):
        return self._module_name

    @module_name.setter
    def module_name(self, value):
        self._module_name = value

    @property
    def object_file_name(self):
        return self._object_file_name

    @object_file_name.setter
    def object_file_name(self, value):
        self._object_file_name = value

    @property
    def name_index_source_file(self):
        return self._name_index_source_file

    @name_index_source_file.setter
    def name_index_source_file(self, value):
        self._name_index_source_file = value

    @property
    def name_index_compiler_pdb_path(self):
        return self._name_index_compiler_pdb_path

    @name_index_compiler_pdb_PATH.setter
    def name_index_COMPILER_PDB_PATH(self, value):
        self._name_index_COMPILER_PDB_PATH = value

    @property
    def adjusted_num_files_contributing(self):
        return self._adjusted_num_files_contributing

    @adjusted_num_files_contributing.setter
    def adjusted_num_files_contributing(self, value):
        self._adjusted_num_files_contributing = value

    def deserialize(self, reader):
        self.module_pointer = reader.parse_unsigned_int_val()
        self.section_contribution.deserialize(reader)
        self.bitfield = reader.parse_unsigned_short_val()
        self.written_since_open = (self.bitfield & 0x01) == 0x01
        self.bitfield >>= 1
        self.spare = self.bitfield & 0x07f
        self.bitfield >>= 1
        self.index_to_tsm_list = self.bitfield & 0x0ff
        self.ec_symbolic_information_enabled = False
        self.stream_number_debug_INFORMATION = reader.parse_unsigned_short_val()
        self.size_local_symbols_DEBUG_INFORMATION = reader.parse_int()
        self.size_line_NUMBER_DEBUG_INFORMATION = reader.parse_int()
        self.size_C13_style_LINE_NUMBER_INFORMATION = reader.parse_int()
        self.num_files_contributing = reader.parse_unsigned_short_val()  # unsigned 16-bit
        reader.align4()
        reader.parse_bytes(4)  # placeholder for offsets_array  # unsigned 32-bit (unused?)
        self.parse_additionals(reader)

    def parse_additionals(self, reader):
        pass

    def dump(self):
        builder = StringBuilder()
        builder.append("ModuleInformation-------------------------------------------\n")
        builder.append(f"modulePointer: {self.module_pointer}\n")
        builder.append(str(self.section_contribution.dump()))
        builder.append(f"\nwrittenSinceOpen: {self.written_since_open}\n")
        builder.append(f"\nceSymbolicInformationEnabled: {self.ec_symbolic_information_enabled}\n")

        builder.append(f"\nspace: {self.spare}\nindexToTSMList: {self.index_to_tsm_list}\nstreamNumberDebugInformation: {self.stream_number_debug_INFORMATION}\nsizeLocalSymbolsDebugInformation: {self.size_local_symbols_DEBUG_INFORMATION}\n")
        builder.append(f"sizeLineNumberDebugInformation: {self.size_line_NUMBER_DEBUG_INFORMATION}\nsizeC13StyleLineNumberInformation: {self.size_C13_style_LINE_NUMBER_INFORMATION}\nnumFilesContributing: {self.num_files_contributing}\n")

        builder.append(self.dump_additionals())

        builder.append(f"\nmoduleName: {self.module_name}\nobjectFileName: {self.object_file_name}\n")
        return str(builder)

    def dump_additionals(self):
        pass

    @property
    def filename_by_offset(self):
        if not hasattr(self, '_filename_by_offset'):
            self._filename_by_offset = {}
        return self._filename_by_offset

    def add_filename_by_offset(self, offset, filename):
        self.filename_by_offset[offset] = filename

    def get_filename_by_offset(self, offset):
        return self.filename_by_offset.get(offset)
