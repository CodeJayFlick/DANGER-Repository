Here is the translation of the Java code into Python:

```Python
class DataTypeParser:
    def __init__(self, allowed_types):
        self.allowed_types = allowed_types

    @staticmethod
    def ensure_is_allowable_type(dt, allowed_types):
        if dt.__class__.__name__ == 'BitFieldDataType':
            if allowed_types != AllowedDataTypes.SIZABLE_DYNAMIC_AND_BITFIELD:
                raise InvalidDataTypeException("Bitfield data-type not allowed")
            return
        match allowed_types:
            case AllowedDataTypes.DYNAMIC | AllowedDataTypes.SIZABLE_DYNAMIC | AllowedDataTypes.SIZABLE_DYNAMIC_AND_BITFIELD:
                if dt.__class__.__name__ == 'FactoryDataType':
                    raise InvalidDataTypeException("Factory data- type not allowed")
                break
            case AllowedDataTypes.FIXED_LENGTH:
                if dt.get_length() <= 0:
                    raise InvalidDataTypeException("Fixed-length data-type required")
                break
            case AllowedDataTypes.STRINGS_AND_FIXED_LENGTH:
                if dt.get_length() <= 0 and not isinstance(dt, AbstractStringDataType):
                    raise InvalidDataTypeException("Fixed- length or string data-type required")
                break
            case AllowedDataTypes.ALL:
                pass
            case _:
                raise InvalidDataTypeException(f"Unknown data type allowance specified: {allowed_types}")

    def parse(self, dt_string, category=None) -> DataType:
        if not dt_string.strip():
            return None

        base_name = self.get_base_string(dt_string)
        named_dt = self.get_named_data_type(base_name, category)

        if named_dt is None:
            raise InvalidDataTypeException("Valid data-type not specified")

        return self.parse_data_type_modifiers(named_dt, dt_string[len(base_name):])

    def parse_data_type_modifiers(self, named_dt: DataType, modifiers_str) -> DataType:
        modifiers = [self.parse_modifier(modifier) for modifier in modifiers_str.split()]
        element_length = named_dt.get_length()
        try:
            for modifier in modifiers:
                if isinstance(modifier, PointerSpecPiece):
                    pointer_size = modifier.get_pointer_size()
                    dt = new PointerDataType(named_dt, pointer_size)
                    element_length = dt.get_length()
                elif isinstance(modifier, ElementSizeSpecPiece):
                    if element_length <= 0:
                        raise InvalidDataTypeException("Non-sizable data-type not allowed")
                    element_size = modifier.get_element_size()
                    dt = create_array_data_type(dt, element_length, element_size)
                elif isinstance(modifier, ArraySpecPiece):
                    element_count = modifier.get_element_count()
                    dt = new ArrayDataType(named_dt, element_count, destination_data_manager)
            return dt
        except InvalidDataTypeException as e:
            raise

    def get_named_data_type(self, base_name: str, category) -> DataType:
        if not self.source_data_type_manager and not self.destination_data_type_manager:
            results = []
            named_dt = find_data_type(self.source_data_type_manager or BuiltInDataTypeManager(), base_name, category, results)
            if named_dt is None:
                return propt_user_for_type(base_name)

    def get_base_string(self, dt_string: str) -> str:
        start_index = 0
        next_index = 1
        while next_index < len(dt_string):
            char = dt_string[next_index]
            if char == '<':
                template_count += 1
            elif char == '>':
                template_count -= 1

    def parse_modifier(self, modifier_str: str) -> DtPiece:
        if not modifier_str.strip():
            return None

        match modifier_str[0]:
            case '*': 
                return PointerSpecPiece(modifier_str)
            case '[': 
                return ArraySpecPiece(modifier_str)
            case ':':
                return BitfieldSpecPiece(modifier_str)

    def create_array_data_type(self, base_dt: DataType, element_length: int, element_size: int) -> DataType:
        if not isinstance(base_dt, TypeDef):
            dt = new ArrayDataType(base_dt, 0, destination_data_manager)
        else:
            dt = (base_dt.get_base_data_type()).clone(destination_data_manager)

    def propt_user_for_type(self, base_name: str) -> DataType:
        return None

class DtPiece:
    pass
```

Please note that Python does not support the concept of interfaces like Java. The `DtPiece` class is a simple placeholder for now and will be replaced with actual classes in the future.

Also, please note that this translation may not work perfectly as it's just an approximation based on my understanding of the code.