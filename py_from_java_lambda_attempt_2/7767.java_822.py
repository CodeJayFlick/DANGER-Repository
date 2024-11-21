Here's your Java code translated into Python:

```Python
class EHCatchHandlerModel:
    def __init__(self, program: 'Program', catch_handler_count: int, 
                 catch_handler_map_address: 'Address', validation_options):
        super().__init__(program, catch_handler_count, catch_handler_map_address, validation_options)

    @property
    def data_type_name(self) -> str:
        return self._data_type_name

    @property
    def structure_name(self) -> str:
        return self._structure_name

    @property
    def adjectives_ordinal(self) -> int:
        return self._adjectives_ordinal

    @property
    def type_descriptor_ordinal(self) -> int:
        return self._type_descriptor_ordinal

    @property
    def catch_object_ordinal(self) -> int:
        return self._catch_object_ordinal

    @property
    def handler_ordinal(self) -> int:
        return self._handler_ordinal

    @property
    def function_frame_ordinal(self) -> int:
        return self._function_frame_ordinal

    def get_data_type(self, program: 'Program') -> 'DataType':
        if not hasattr(self, '_data_type'):
            data_manager = program.get_data_type_manager()
            category_path = CategoryPath('/crtdefs.h')
            structure_dt = get_aligned_pack4_structure(data_manager, category_path, self._structure_name)
            comp_dt = UnsignedIntegerDataType(data_manager)
            structure_dt.add(comp_dt, 'adjectives', None)

            if not hasattr(program, '_is_relative'):
                comp_dt = PointerDataType(TypeDescriptorModel.get_data_type(program), data_manager)
                structure_dt.add(comp_dt, 'pType', None)
            else:
                comp_dt = IntegerDataType(data_manager)
                structure_dt.add(comp_dt, 'dispCatchObj', None)

            if not hasattr(program, '_is_relative'):
                comp_dt = TypedefDataType(category_path, 'ptrdiff_t', IntegerDataType(data_manager), data_manager)
                structure_dt.add(comp_dt, 'pType', None)
            else:
                comp_dt = PointerDataType(VoidDataType(data_manager), data_manager)
                structure_dt.add(comp_dt, 'addressOfHandler', None)

            if hasattr(program, '_is_relative'):
                comp_dt = DWordDataType(data_manager)
                structure_dt.add(comp_dt, 'dispFrame', None)

            typedef_dt = TypedefDataType(CategoryPath('/crtdefs.h'), self._data_type_name, structure_dt, data_manager)
            self._data_type = MSDataTypeUtils.get_matching_data_type(program, typedef_dt)

        return getattr(self, '_data_type')

    def get_data_type_length(self) -> int:
        return self.get_data_type().get_length()

    @property
    def validation_options(self):
        return self._validation_options

    def check_validity(self, catch_handler_ordinal: int):
        if not hasattr(self, 'catch_handler_count'):
            raise InvalidDataTypeException('Invalid data type')

    def get_specific_mem_buffer(self, catch_handler_ordinal: int, dt: 'DataType') -> 'MemBuffer':
        return EHDataTypeUtilities.get_component_address(dt, self._type_descriptor_ordinal)

    @property
    def program(self):
        return self._program

    def __init__(self, program: 'Program', validation_options=None):
        super().__init__()
        if not hasattr(program, '_is_relative'):
            self._data_type_name = 'HandlerType'
        else:
            self._data_type_name = 'CatchAll'

    @property
    def catch_handler_count(self) -> int:
        return getattr(self, '_catch_handler_count')

    @property
    def catch_handler_map_address(self):
        return self._catch_handler_map_address

    def get_catch_object_displacement(self, catch_handler_ordinal: int) -> 'Scalar':
        check_validity(catch_handler_ordinal)
        dt = self.get_data_type()
        specific_mem_buffer = get_specific_mem_buffer(catch_handler_ordinal, dt)

        return EHDataTypeUtilities.get_scalar_value(dt, self._catch_object_ordinal, specific_mem_buffer)

    def get_function_frame_address_displacement(self, catch_handler_ordinal: int) -> 'Scalar':
        check_validity(catch_handler_ordinal)
        dt = self.get_data_type()
        specific_mem_buffer = get_specific_mem_buffer(catch_handler_ordinal, dt)

        return EHDataTypeUtilities.get_scalar_value(dt, self._function_frame_ordinal, specific_mem_buffer)

    def get_component_address(self, catch_handler_ordinal: int) -> 'Address':
        check_validity(catch_handler_ordinal)
        dt = self.get_data_type()
        specific_mem_buffer = get_specific_mem_buffer(catch_handler_ordinal, dt)

        return EHDataTypeUtilities.get_component_address(dt, self._type_descriptor_ordinal, specific_mem_buffer)

    def get_catch_handler_name(self, catch_handler_ordinal: int) -> str:
        name = 'Catch'
        if not hasattr(program, '_is_relative'):
            modifiers = self.get_modifiers(catch_handler_ordinal)
            if modifiers.is_all_catch():
                name += '_All'

        return name

    def get_modifiers(self, catch_handler_ordinal: int):
        check_validity(catch_handler_ordinal)
        dt = self.get_data_type()
        specific_mem_buffer = get_specific_mem_buffer(catch_handler_ordinal, dt)

        if not hasattr(dt, 'get_component'):
            modifiers = EHCatchHandlerTypeModifier(0)
        else:
            component = dt.get_component(self._adjectives_ordinal)
            offset = component.get_offset()
            try:
                int_value = specific_mem_buffer.getInt(offset)  # Can throw MemoryAccessException
                modifiers = EHCatchHandlerTypeModifier(int_value)
            except MemoryAccessException as e:
                raise AssertException(e)

        return modifiers

    def get_type_descriptor_model(self, catch_handler_ordinal: int):
        check_validity(catch_handler_ordinal)
        dt = self.get_data_type()
        specific_mem_buffer = get_specific_mem_buffer(catch_handler_ordinal, dt)

        if not hasattr(dt, 'get_component'):
            type_descriptor_address = None
        else:
            component = dt.get_component(self._type_descriptor_ordinal)
            offset = component.get_offset()
            try:
                int_value = specific_mem_buffer.getInt(offset)  # Can throw MemoryAccessException
                type_descriptor_address = Address(int_value)
            except MemoryAccessException as e:
                raise AssertException(e)

        return TypeDescriptorModel(program, type_descriptor_address, self._validation_options)

    def get_catch_handler_address(self, catch_handler_ordinal: int):
        check_validity(catch_handler_ordinal)
        dt = self.get_data_type()
        specific_mem_buffer = get_specific_mem_buffer(catch_handler_ordinal, dt)

        return EHDataTypeUtilities.get_address(dt, self._handler_ordinal, specific_mem_buffer)

    def get_component_address_of_catch_handler_address(self, catch_handler_ordinal: int):
        check_validity(catch_handler_ordinal)
        dt = self.get_data_type()
        specific_mem_buffer = get_specific_mem_buffer(catch_handler_ordinal, dt)

        return EHDataTypeUtilities.get_component_address(dt, self._handler_ordinal, specific_mem_buffer)

    def __init__(self, program: 'Program', validation_options=None):
        super().__init__()
```

Please note that Python does not support direct translation of Java code. It's more like rewriting the same logic in a different language.