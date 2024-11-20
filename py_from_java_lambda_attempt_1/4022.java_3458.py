Here is the translation of the Java code into Python:

```Python
class AddBlockModel:
    def __init__(self, tool, program):
        self.tool = tool
        self.program = program
        self.name_indexer = {}
        self.load_block_names()

    def set_change_listener(self, listener):
        self.listener = listener

    def set_block_name(self, name):
        self.block_name = name
        self.validate_info()
        self.listener.state_changed(None)

    def set_comment(self, comment):
        self.comment = comment

    def set_start_address(self, start_addr):
        self.start_addr = start_addr
        self.validate_info()
        self.listener.state_changed(None)

    def set_length(self, length):
        self.length = length
        self.validate_info()
        self.listener.state_changed(None)

    def set_file_offset(self, file_offset):
        self.file_bytes_offset = file_offset
        self.validate_info()
        self.listener.state_changed(None)

    def set_file_bytes(self, file_bytes):
        self.file_bytes = file_bytes
        self.validate_info()
        self.listener.state_changed(None)

    def set_initial_value(self, initial_value):
        self.initial_value = initial_value
        self.validate_info()
        self.listener.state_changed(None)

    def set_block_type(self, block_type):
        self.block_type = block_type
        if block_type == 'BIT_MAPPED':
            self.is_read = True
            self.is_write = True
            self.is_execute = False
            self.is_volatile = False
            self.is_overlay = False
            self.scheme_dest_byte_count = 8
            self.scheme_src_byte_count = 1
        elif block_type == 'BYTE_MAPPED':
            self.is_read = True
            self.is_write = True
            self.is_execute = False
            self.is_volatile = False
            self.is_overlay = False
            self.scheme_dest_byte_count = 8
            self.scheme_src_byte_count = 1

    def set_read(self, b):
        self.is_read = b

    def set_write(self, b):
        self.is_write = b

    def set_execute(self, b):
        self.is_execute = b

    def set_volatile(self, b):
        self.is_volatile = b

    def set_overlay(self, b):
        self.is_overlay = b
        if not is_read and not is_write:
            print("Warning! Overlay block must be read or write.")

    def set_initialized_type(self, initialized_type):
        self.initialized_type = initialized_type
        if initialized_type == 'INITIALIZED_FROM_FILE_BYTES':
            if file_bytes_offset < 0 or file_bytes_offset >= len(file_bytes):
                print("Please enter a valid file bytes offset.")
                return False

    def dispose(self):
        self.tool = None
        self.program = None

    def validate_info(self):
        message = ''
        is_valid = (has_valid_name() and has_valid_start_address() and has_valid_length()
                    and not has_memory_conflicts())
        if not is_valid:
            print(message)
        return is_valid

    def execute(self):
        if self.validate_info():
            command = self.create_add_block_command()
            if self.tool.execute(command, self.program):
                return True
            else:
                message = command.status_msg
                print(message)
                return False
        else:
            return False

    def create_add_block_command(self):
        source = ''
        if self.block_type == 'BIT_MAPPED':
            return AddBitMappedMemoryBlockCmd(self.block_name, self.comment, source,
                                               self.start_addr, self.length, self.is_read,
                                               self.is_write, self.is_execute, self.is_volatile)
        elif self.block_type == 'BYTE_MAPPED':
            byte_mapping_scheme = ByteMappingScheme(self.scheme_dest_byte_count,
                                                     self.scheme_src_byte_count)
            return AddByteMappedMemoryBlockCmd(self.block_name, self.comment, source,
                                               self.start_addr, self.length, self.is_read,
                                               self.is_write, self.is_execute, self.is_volatile,
                                               byte_mapping_scheme)

    def create_non_mapped_memory_block(self):
        if self.initialized_type == 'INITIALIZED_FROM_FILE_BYTES':
            return AddFileBytesMemoryBlockCmd(self.block_name, self.comment, source,
                                              self.start_addr, self.length, self.is_read,
                                              self.is_write, self.is_execute)
        elif self.initialized_type == 'INITIALIZED_FROM_VALUE':
            return AddInitializedMemoryBlockCmd(self.block_name, self.comment, source,
                                               self.start_addr, self.length, self.is_read,
                                               self.is_write)

    def has_file_bytes_info_needed(self):
        if self.initialized_type != 'INITIALIZED_FROM_FILE_BYTES':
            return True
        if file_bytes is None:
            message = "Please select a FileBytes entry"
            print(message)
            return False

    def has_initial_value_needed(self):
        if self.initialized_type == 'INITIALIZED_FROM_VALUE':
            if initial_value >= 0 and initial_value <= 255:
                return True
            else:
                message = "Please enter a valid initial byte value"
                print(message)
                return False

    def is_overlay_if_other_space(self):
        if start_addr.get_address_space() == 'OTHER_SPACE' and not self.is_overlay:
            message = f"Blocks defined in the {start_addr.get_address_space()} space must be overlay blocks."
            print(message)
            return False
        else:
            return True

    def has_mapped_address_needed(self):
        if block_type != 'BIT_MAPPED' and block_type != 'BYTE_MAPPED':
            return True
        if base_addr is None:
            message = "Please enter a valid mapped region Source Address"
            print(message)
            return False

    def has_no_memory_conflicts(self):
        end_addr = start_addr + (length - 1)
        intersect_range = program.get_memory().intersect_range(start_addr, end_addr)
        if not intersect_range.is_empty():
            message = f"Block address conflict: {intersect_range}"
            print(message)
            return False
        else:
            return True

    def has_valid_length(self):
        limit = 0x10000000
        space_limit = start_addr.get_address_space().get_max_address() - start_addr
        if space_limit >= 0:
            limit = min(limit, space_limit + 1)
        if length > 0 and length <= limit:
            return True
        else:
            message = f"Please enter a valid Length: 1 to {limit}"
            print(message)
            return False

    def has_valid_start_address(self):
        if start_addr is not None:
            return True
        else:
            message = "Please enter a valid Start Address"
            print(message)
            return False

    def load_block_names(self):
        memory = self.program.get_memory()
        blocks = memory.get_blocks()
        for block in blocks:
            name_indexer[block.name] = 1

class AddBitMappedMemoryBlockCmd:
    pass

class AddByteMappedMemoryBlockCmd:
    pass

class AddFileBytesMemoryBlockCmd:
    pass

class AddInitializedMemoryBlockCmd:
    pass
```

Please note that this is a direct translation of the Java code into Python, and it may not be perfect. The original code had many classes and methods which were used to create commands for adding memory blocks in Ghidra. This translated code does not include those details as they are specific to the Ghidra framework.