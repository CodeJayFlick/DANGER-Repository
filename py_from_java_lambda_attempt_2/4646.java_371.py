Here is the translation of the Java code into Python:

```Python
class StatementProgramPrologue:
    TOTAL_LENGTH_FIELD_LEN = 4
    PRE_PROLOGUE_LEN = 4 + 2 + 4

    def __init__(self, reader):
        self.total_length = int.from_bytes(reader.read(4), 'little')
        self.version = int.from_bytes(reader.read(2), 'little')

        if self.version != 2:
            raise ValueError("Only DWARF v2 is supported.")

        self.prologue_length = int.from_bytes(reader.read(4), 'little')
        self.minimum_instruction_length = reader.read(1)[0]
        self.default_is_statement = bool(reader.read(1)[0])
        self.line_base = reader.read(1)[0]
        self.line_range = reader.read(1)[0]
        self.opcode_base = reader.read(1)[0]

        standard_opcode_lengths_len = int.from_bytes(reader.read(1), 'little')
        self.standard_opcode_lengths = reader.read(standard_opcode_lengths_len)

        while True:
            dir_length = int.from_bytes(reader.read(4), 'little')
            if dir_length == 0:
                break
            include_directories.append(reader.read(dir_length).decode('utf-8'))

        while True:
            entry = FileEntry(reader)
            if not entry.filename:
                break
            file_names.append(entry)

    def get_total_length(self):
        return self.total_length

    def get_version(self):
        return self.version & 0xffff

    def get_prologue_length(self):
        return self.prologue_length

    def get_minimum_instruction_length(self):
        return self.minimum_instruction_length & 0xff

    def is_default_is_statement(self):
        return self.default_is_statement

    def get_line_base(self):
        return self.line_base & 0xff

    def get_line_range(self):
        return self.line_range & 0xff

    def get_opcode_base(self):
        return self.opcode_base & 0xff

    def get_standard_opcode_lengths(self):
        return self.standard_opcode_lengths

    def get_include_directories(self):
        return include_directories

    def get_file_names(self):
        return file_names

    def get_filename_by_index(self, file_index):
        return file_names[file_index - 1]

    def get_directory_by_index(self, directory_index):
        if directory_index == 0:
            return '.'
        return include_directories[directory_index - 1]


class FileEntry:
    def __init__(self, reader):
        self.filename = reader.read(reader.read(4)).decode('utf-8')

    def get_filename(self):
        return self.filename
```

Please note that this translation is not a direct conversion from Java to Python. The original code uses some specific features of the Java language (like `int TOTAL_LENGTH_FIELD_LEN`), which are not directly translatable into Python.