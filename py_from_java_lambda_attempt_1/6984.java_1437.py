Here is the translation of the given Java code into Python:

```Python
class PcodeFunctionParser:
    def __init__(self, program):
        self.program = program

    READABLE_ASCII_LOWER_BOUND = 32
    READABLE_ASCII_UPPER_BOUND = 126
    BUFFER_LENGTH = 20
    CALL_INSTRUCTION = "CALL"

    def parse_function_for_call_data(self, pcode_ops, address_to_candidate_data, variadic_function_names):
        if not (pcode_ops and address_to_candidate_data and variadic_function_names) or self.program is None:
            return []

        function_call_data_list = []
        for ast in pcode_ops:
            first_node = ast.get_input(0)
            if first_node is None:
                continue

            if ast.mnemonic == CALL_INSTRUCTION:
                function_manager = self.program.function_manager
                function = function_manager.get_function_at(first_node.address)

                if not (function and variadic_function_names):
                    return []

                function_name = function.name
                if function_name in variadic_function_names:
                    inputs = ast.inputs

                    has_defined_format_string = search_for_variadic_call_data(ast, address_to_candidate_data,
                                                                              function_call_data_list, function_name)

                    if not has_defined_format_string:
                        search_for_hidden_format_strings(ast, function_call_data_list, function_name)
        return function_call_data_list

    def search_for_variadic_call_data(self, ast, address_to_candidate_data, function_call_data_list, function_name):
        has_defined_format_string = False
        inputs = ast.inputs[1:]

        for i in range(len(inputs)):
            v = inputs[i]
            data = None
            ram_space_address = self.convert_address_to_ram_space(v.address)

            if ram_space_address in address_to_candidate_data:
                data = address_to_candidate_data.get(ram_space_address)
                function_call_data_list.append(FunctionCallData(ast.seqnum.target, function_name,
                                                                 data.default_value_representation))
                has_defined_format_string = True

        return has_defined_format_string

    def search_for_hidden_format_strings(self, ast, function_call_data_list, function_name):
        inputs = ast.inputs[1:]

        for i in range(len(inputs)):
            v = inputs[i]
            format_string_candidate = self.find_format_string(v.address)

            if format_string_candidate is None:
                continue
            elif "%" in format_string_candidate:
                function_call_data_list.append(FunctionCallData(ast.seqnum.target, function_name,
                                                                 format_string_candidate))
        return

    def convert_address_to_ram_space(self, address):
        address_string = str(address)
        ram_space_address = self.program.address_factory.get_address(address_string)

        return ram_space_address

    def find_format_string(self, address):
        if not address.address_space.is_constant_space():
            return None
        else:
            ram_space_address = self.convert_address_to_ram_space(address)

            memory_buffer = MemoryBufferImpl(self.program.memory, ram_space_address)
            settings = SettingsImpl()

            string_data_instance = StringDataInstance(StringDataType(), memory_buffer, settings, self.BUFFER_LENGTH).get_string_value()
            if string_data_instance is None:
                return None

        format_string_candidate = ""

        for i in range(len(string_data_instance)):
            c = string_data_instance[i]
            if not (self.READABLE_ASCII_LOWER_BOUND <= ord(c) <= self.READABLE_ASCII_UPPER_BOUND):
                break
            else:
                format_string_candidate += str(c)

        return format_string_candidate

    def is_ascii_readable(self, c):
        return READABLE_ASCII_LOWER_BOUND <= ord(c) <= READABLE_ASCII_UPPER_BOUND


class FunctionCallData:
    def __init__(self, target, function_name, default_value_representation):
        self.target = target
        self.function_name = function_name
        self.default_value_representation = default_value_representation

```

Note: The `MemoryBufferImpl`, `SettingsImpl` and other classes are not directly translatable to Python. They seem to be part of the Ghidra framework, which is a reverse engineering tool.