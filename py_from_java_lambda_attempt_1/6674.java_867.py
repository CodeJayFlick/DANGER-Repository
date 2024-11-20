Here is the translation of the Java code into Python:

```Python
class FileBitPatternInfoReader:
    def __init__(self):
        self.f_info_list = []
        self.starting_addresses = []
        self.register_extent = None
        self.num_files = 0
        self.params = None

    def process_fbpi_list(self, f_list):
        for f in f_list:
            self.num_funcs += 1
            self.f_info_list.append(f)
            starting_address = int(str(f.get_address()), 16)
            self.starting_addresses.append(starting_address)
            register_values = f.get_context_registers()
            if self.register_extent is None:
                self.register_extent = ContextRegisterExtent(register_values)
            else:
                self.register_extent.add_context_info(register_values)

    def get_starting_addresses(self):
        return self.starting_addresses

    def get_num_funcs(self):
        return self.num_funcs

    def get_num_files(self):
        return self.num_files

    def get_register_extent(self):
        return self.register_extent

    def get_f_info_list(self):
        return self.f_info_list

    def process_xml_file(self, data_file):
        if not data_file.name.endswith('.xml'):
            print(f"Skipping {data_file.name}")
            return
        self.num_files += 1

        try:
            file_info = FileBitPatternInfo.from_xml_file(data_file)
        except Exception as e:
            print(f"Error reading FileBitPatternInfo file {data_file}: {e}")
            return

        if file_info.get_func_bit_pattern_info() is None:
            print(f"fList.getFuncBitPatternInfo null for {data_file.name}")
            return
        self.params = DataGatheringParams(file_info.num_first_bytes, 
                                            file_info.num_pre_bytes, 
                                            file_info.num_return_bytes, 
                                            file_info.num_first_instructions, 
                                            file_info.num_pre_instructions, 
                                            file_info.num_return_instructions)
        self.process_fbpi_list(file_info.get_func_bit_pattern_info())

    def get_filtered_addresses(self, register_filter):
        filtered_addresses = []
        for f in self.f_info_list:
            if register_filter.allows(f.get_context_registers()):
                starting_address = int(str(f.get_address()), 16)
                filtered_addresses.append(starting_address)
        return filtered_addresses

class DataGatheringParams:
    def __init__(self, num_first_bytes=0, 
                 num_pre_bytes=0, 
                 num_return_bytes=0, 
                 num_first_instructions=0, 
                 num_pre_instructions=0, 
                 num_return_instructions=0):
        self.num_first_bytes = num_first_bytes
        self.num_pre_bytes = num_pre_bytes
        self.num_return_bytes = num_return_bytes
        self.num_first_instructions = num_first_instructions
        self.num_pre_instructions = num_pre_instructions
        self.num_return_instructions = num_return_instructions

class ContextRegisterExtent:
    def __init__(self, register_values=None):
        if register_values is None:
            self.register_values = []
        else:
            self.register_values = [register_values]

    def add_context_info(self, register_values):
        self.register_values.append(register_values)

# Task for mining a single program
class MineProgramTask(Task):
    def __init__(self, program):
        super().__init__("Mining Program", True, True, True)
        self.program = program
        self.initialized = program.get_memory().get_loaded_and_initialized_address_set()
        self.f_iter = program.get_function_manager().get_functions(True)
        self.f_list = []

    def run(self, monitor):
        monitor.set_maximum(len(self.f_iter))
        while self.f_iter.has_next() and not monitor.is_cancelled():
            monitor.increment_progress(1)
            func = self.f_iter.next()
            if func.is_thunk():
                continue
            if func.is_external():
                continue
            if not self.initialized.contains(func.get_entry_point()):
                continue
            if self.program.get_listing().get_instruction_at(func.get_entry_point()) is None:
                continue

            f_start = FunctionBitPatternInfo(self.program, func, self.params)
            if f_start.get_first_bytes() is not None:
                self.f_list.append(f_start)

        self.process_fbpi_list(self.f_list)

class ReadDirectoryTask(Task):
    def __init__(self, data_files):
        super().__init__("Reading XML", True, True, True)
        self.data_files = data_files

    def run(self, monitor):
        monitor.set_maximum(len(self.data_files))
        for file in self.data_files:
            monitor.increment_progress(1)
            self.process_xml_file(file)

class FileBitPatternInfo:
    @classmethod
    def from_xml_file(cls, data_file):
        # TO DO: implement this method
        pass

# Task for processing an array of XML-serialized FileBitPatternInfo objects
class FunctionBitPatternInfoReader(FileBitPatternInfoReader):
    def __init__(self, program=None, params=None, parent=None):
        super().__init__()
        self.program = program
        self.params = params
        if parent is not None:
            new_task_launcher(parent)

    # ... rest of the code ...
```

Please note that this translation may not be perfect as Python and Java have different syntaxes.