class EHDataTypeUtilities:
    def __init__(self):
        pass

    @staticmethod
    def get_eh_state_value(data_type: 'DataType', component_ordinal: int, mem_buffer: 'MemBuffer') -> int:
        return EHDataTypeUtilities.get_integer_value(data_type, component_ordinal, mem_buffer)

    @staticmethod
    def get_count(data_type: 'DataType', component_ordinal: int, mem_buffer: 'MemBuffer') -> int:
        return EHDataTypeUtilities.get_integer_value(data_type, component_ordinal, mem_buffer)

    @staticmethod
    def get_integer_value(data_type: 'DataType', component_ordinal: int, mem_buffer: 'MemBuffer') -> int:
        scalar = EHDataTypeUtilities.get_scalar_value(data_type, component_ordinal, mem_buffer)
        return int(scalar.value)

    @staticmethod
    def get_scalar_value(data_type: 'DataType', component_ordinal: int, mem_buffer: 'MemBuffer') -> 'Scalar':
        comp = EHDataTypeUtilities.get_component(data_type, component_ordinal, mem_buffer)
        if comp is None:
            raise ValueError("Couldn't get component " + str(component_ordinal) + " of " + data_type.name)

        address = EHDataTypeUtilities.get_component_address(comp, mem_buffer)
        dt = comp.data_type
        length = comp.length

        value = dt.value(mem_buffer.memory, comp.default_settings(), length)
        if isinstance(value, 'Scalar'):
            return value
        raise ValueError("Component " + str(component_ordinal) + " of " + data_type.name + " is a " + dt.name + " data type, which doesn't produce a Scalar value.")

    @staticmethod
    def get_component_address(comp: 'DataTypeComponent', mem_buffer: 'MemBuffer') -> Address:
        offset = comp.offset

        try:
            return mem_buffer.address.add(offset)
        except AddressOutOfBoundsException as e:
            raise ValueError("Can't get component " + str(comp.ordinal) + " from memory buffer for data type " + comp.parent.name, e)

    @staticmethod
    def get_component(data_type: 'DataType', component_ordinal: int, mem_buffer: 'MemBuffer') -> 'DataTypeComponent':
        if data_type is None:
            raise ValueError("Data type cannot be null.")

        if isinstance(data_type, DynamicDataType):
            return (data_type).get_component(component_ordinal, mem_buffer)
        elif isinstance(data_type, TypeDef):
            dt = (data_type).base_data_type
        else:
            struct = data_type
            return struct.component(component_ordinal)

    @staticmethod
    def get_address(data_type: 'DataType', component_ordinal: int, mem_buffer: 'MemBuffer') -> Address:
        comp = EHDataTypeUtilities.get_component(data_type, component_ordinal, mem_buffer)
        if comp is None:
            raise ValueError("Couldn't get component " + str(component_ordinal) + " of " + data_type.name)

        return EHDataTypeUtilities.get_component_address(comp, mem_buffer)

    @staticmethod
    def create_plate_comment_if_needed(program: 'Program', prefix: str, data_type_name: str, suffix: str, address: Address, apply_options: 'DataApplyOptions') -> str:
        listing = program.listing

        existing_comment = listing.comment(address)
        if not apply_options.create_comments():
            return existing_comment
        if data_type_name is None or not apply_options.should_create_labels():
            return None  # Already have one with dataTypeName.

        applied_prefix = prefix if prefix else ""
        applied_suffix = suffix if suffix else ""

        applied_existing = existing_comment if existing_comment else "\n"
        applied_comment = (applied_existing + applied_prefix + data_type_name + applied_suffix).strip()
        listing.set_comment(address, applied_comment)
        return applied_comment

    @staticmethod
    def create_symbol_if_needed(program: 'Program', prefix: str, data_type_name: str, suffix: str, address: Address, apply_options: 'DataApplyOptions') -> 'Symbol':
        if not apply_options.should_create_labels():
            return None  # Already have one with dataTypeName.

        symbol_table = program.symbol_table
        primary_symbol = symbol_table.get_primary_symbol(address)
        if primary_symbol and primary_symbol.source != SourceType.DEFAULT:
            return None  # Not needed. Non-default symbol already there.

        address_appended_name = SymbolUtilities.get_address_appended_name(prefix, address)

        try:
            return symbol_table.create_label(address, address_appended_name, SourceType.ANALYSIS)
        except InvalidInputException as e:
            raise ValueError("Failed to create label at " + str(address), e)

    @staticmethod
    def create_function_if_needed(program: 'Program', function_address: Address) -> bool:
        if not isValid_address(program, function_address):
            return False

        listing = program.listing
        instruction = listing.get_instruction_at(function_address)
        if instruction is None:
            cmd = DisassembleCommand(function_address, None, True)
            try:
                cmd.apply_to(program)
            except InvalidInputException as e:
                raise ValueError("Failed to disassemble at " + str(function_address), e)

        function_manager = program.function_manager
        function = function_manager.get_function_at(function_address)
        if function is None:
            cmd = CreateFunctionCmd(function_address)
            try:
                cmd.apply_to(program)
            except InvalidInputException as e:
                raise ValueError("Failed to create function at " + str(function_address), e)

        return True

    @staticmethod
    def is_valid_address(program: 'Program', address: Address) -> bool:
        if address is None:
            raise ValueError("address cannot be null.")

        return program.memory.get_loaded_and_initialized_address_set().contains(address)

    @staticmethod
    def is_valid_for_function(program: 'Program', function_address: Address) -> bool:
        if not isValid_address(program, function_address):
            return False

        listing = program.listing
        instruction = listing.get_instruction_at(function_address)
        undefined_data = listing.get_undefined_data_at(function_address)

        return (instruction is not None or undefined_data is not None)


class DataTypeComponent:
    def __init__(self, parent: 'DataType', ordinal: int):
        self.parent = parent
        self.ordinal = ordinal

    @property
    def offset(self) -> int:
        pass  # To be implemented


class MemBuffer:
    def __init__(self, memory: Memory, address: Address):
        self.memory = memory
        self.address = address


class Program:
    def __init__(self):
        pass

    @property
    def listing(self) -> 'Listing':
        pass  # To be implemented

    @property
    def function_manager(self) -> 'FunctionManager':
        pass  # To be implemented

    @property
    def memory(self) -> Memory:
        pass  # To be implemented


class DynamicDataType(DataType):
    def __init__(self, base_data_type: 'DataType'):
        self.base_data_type = base_data_type

    def get_component(self, ordinal: int, mem_buffer: MemBuffer) -> DataTypeComponent:
        pass  # To be implemented


class TypeDef(DataType):
    def __init__(self, base_data_type: 'DataType'):
        self.base_data_type = base_data_type

    @property
    def base_data_type(self) -> 'DataType':
        return self.base_data_type


class Structure(DataType):
    def __init__(self):
        pass

    def get_component(self, ordinal: int) -> DataTypeComponent:
        pass  # To be implemented


class SymbolTable:
    def __init__(self, program: Program):
        self.program = program

    @property
    def primary_symbol(self) -> 'Symbol':
        pass  # To be implemented

    def get_symbols_as_iterator(self, address: Address) -> Iterator['Symbol']:
        pass  # To be implemented


class FunctionManager:
    def __init__(self, program: Program):
        self.program = program

    @property
    def function_table(self) -> 'FunctionTable':
        pass  # To be implemented

    def get_function_at(self, address: Address) -> 'Function':
        pass  # To be implemented


class Function:
    def __init__(self, start_address: Address):
        self.start_address = start_address
