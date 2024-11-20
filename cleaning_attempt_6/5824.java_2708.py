class PCodeTestControlBlock:
    INITIAL_FUNCTION_NAME = "<NONE>"
    UNKNOWN_FUNCTION_NAME = "<UNKNOWN>"

    MAIN_CONTROL_BLOCK_MAGIC = "AbCdEFgH"

    test_info_struct = None  # TestInfo structure
    group_info_struct = None  # GroupInfo structure

    def __init__(self, program, restricted_set, start_of_control_block, test_file,
                 cached_program_path, apply_struct, test_results):
        super().__init__(program, start_of_control_block)
        self.restricted_set = restricted_set
        self.test_file = test_file
        self.cached_program_path = cached_program_path
        self.test_results = test_results

    @staticmethod
    def get_main_control_block(program, test_file, restricted_set,
                                cached_program_path, test_info_struct, group_info_struct,
                                apply_struct, test_results):
        PCodeTestControlBlock.test_info_struct = test_info_struct
        PCodeTestControlBlock.group_info_struct = group_info_struct

        memory = program.get_memory()
        magic_bytes = get_char_array_bytes(program, PCodeTestControlBlock.MAIN_CONTROL_BLOCK_MAGIC)

        start_of_control_block = find_bytes(memory, restricted_set, magic_bytes)
        if start_of_control_block is None:
            raise InvalidControlBlockException("TestInfo structure not found")

        return PCodeTestControlBlock(program, restricted_set, start_of_control_block,
                                      test_file, cached_program_path, apply_struct, test_results)

    def __str__(self):
        return f"{type(self).__name__}:{self.test_file}"

    @property
    def test_groups(self):
        return self._test_groups

    @test_groups.setter
    def test_groups(self, value):
        self._test_groups = value

    # ... other methods ...

class InvalidControlBlockException(Exception):
    pass

def get_char_array_bytes(program, magic_bytes):
    # implement this function in Python
    pass

def find_bytes(memory, restricted_set, magic_bytes):
    # implement this function in Python
    pass

# Other functions ...
