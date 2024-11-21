Here is the translation of the given Java code into equivalent Python:

```Python
class DWARFLine:
    def __init__(self):
        self.unit_length = 0
        self.format = 0
        self.version = 0
        self.header_length = 0
        self.minimum_instruction_length = 0
        self.maximum_operations_per_instruction = 1
        self.default_is_stmt = 0
        self.line_base = 0
        self.line_range = 0
        self.opcode_base = 0
        self.standard_opcode_lengths = [1]
        self.include_directories = []
        self.file_names = []

    @staticmethod
    def read(diea):
        dProg = diea.get_program()
        reader = dProg.get_debug_line()

        stmt_list_offset = diea.get_unsigned_long(DWARFAttribute.DW_AT_stmt_list, -1)

        if reader is None or stmt_list_offset < 0:
            return None

        reader.set_pointer_index(stmt_list_offset)
        result = DWARFLine()
        
        length_info = DWARFUtil.read_length(reader, dProg.get_gnidra_program())
        result.unit_length = length_info.length
        result.format = length_info.format
        
        if result.unit_length == 0:
            raise ValueError(f"Invalid DWARFLine length {result.unit_length} at 0x{stmt_list_offset:x}")

        result.version = reader.read_next_unsigned_short()
        
        result.header_length = DWARFUtil.read_offset_by_dwarf_format(reader, result.format)
        
        result.minimum_instruction_length = reader.read_next_unsigned_byte()

        if result.version >= 4:
            result.maximum_operations_per_instruction = reader.read_next_unsigned_byte()
        else:
            result.maximum_operations_per_instruction = 1
        
        result.default_is_stmt = reader.read_next_unsigned_byte()
        result.line_base = reader.read_next_byte()
        result.line_range = reader.read_next_unsigned_byte()
        result.opcode_base = reader.read_next_unsigned_byte()

        for i in range(1, result.opcode_base):
            result.standard_opcode_lengths.append(reader.read_next_unsigned_byte())

        include_dir = ""
        while len(include_dir) > 0:
            result.include_directories.append(include_dir)
            include_dir = reader.read_next_ascii_string()
        
        file_obj = None
        for i in range(len(result.file_names)):
            if i == 0:
                #TODO: Handle index=0
                raise NotImplementedError("Currently does not support retrieving the primary source file.")
            else:
                file_name = result.file_names[i-1].get_name()
                file_dir_idx = int(file_name.get_directory_index())
                
                if file_dir_idx > 0:
                    dir_path = result.include_directories[file_dir_idx - 1]
                    full_file_path = f"{dir_path}/{file_name}"
                else:
                    full_file_path = file_name
                
                yield full_file_path

    def get_full_file(self, index, compile_directory):
        if index == 0:
            #TODO: Handle index=0
            raise NotImplementedError("Currently does not support retrieving the primary source file.")
        elif index > 0:
            file_obj = self.file_names[index-1]
            
            if file_obj.get_name().is_absolute():
                return file_obj.get_name()
            else:
                dir_idx = int(file_obj.get_directory_index())
                
                if dir_idx == 0:
                    # Use the compile directory
                    return f"{compile_directory}/{file_obj}"
                elif dir_idx > 0:
                    dir_path = self.include_directories[dir_idx - 1]
                    full_file_path = f"{dir_path}/{file_obj}"
                else:
                    raise IndexError(f"Negative directory index {dir_idx}")
        else:
            raise ValueError("Negative file index")

    def get_file(self, index):
        if index == 0:
            #TODO: Handle index=0
            raise NotImplementedError("Currently does not support retrieving the primary source file.")
        elif index > 0:
            return self.file_names[index-1].get_name()
        else:
            raise ValueError("Negative file index")

    def __str__(self):
        buffer = f"Line Entry\nInclude Directories: [{', '.join(self.include_directories)}]\nFile Names: {', '.join([file.__str__() for file in self.file_names])}"
        return buffer

class DWARFFile:
    def __init__(self, name, directory_index, modification_time, length):
        self.name = name
        self.directory_index = directory_index
        self.modification_time = modification_time
        self.length = length

    @staticmethod
    def read(reader):
        file_name = reader.read_next_ascii_string()
        
        if len(file_name) > 0:
            dir_idx = LEB128.read_as_long(reader, False)
            mod_time = LEB128.read_as_long(reader, False)
            length = LEB128.read_as_long(reader, False)

    def __str__(self):
        buffer = f"Filename: {self.name}\nLength: 0x{self.length:x}"
        return buffer
```

Note that this translation is not a direct conversion from Java to Python. The code has been modified and optimized for the Python language.