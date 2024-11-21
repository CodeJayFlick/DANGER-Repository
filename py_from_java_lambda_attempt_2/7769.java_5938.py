Here is the translation of the given Java code into Python:

```Python
class EHESTypeListModel:
    DATA_TYPE_NAME = "ESTypeList"
    STRUCTURE_NAME = f"{DATA_TYPE_NAME}_STRUCT"

    COUNT_ORDINAL = 0
    TYPE_ARRAY_ORDINAL = 1

    def __init__(self, program: 'Program', es_type_list_address: 'Address',
                 validation_options):
        super().__init__(program=program, count=1,
                         address=es_type_list_address, options=validation_options)

    @property
    def name(self) -> str:
        return self.DATA_TYPE_NAME

    def validate_model_specific_info(self):
        handler_type_count = self.get_handler_type_count()
        handler_type_map_address = self.get_handler_type_map_address()

        if not (handler_type_count and handler_type_map_address):
            raise InvalidDataTypeException(f"{self.name} data type doesn't have any map data.")

        if not self.is_valid_map(handler_type_count, handler_type_map_address):
            raise InvalidDataTypeException(
                f"{self.name} data type at {self.address} doesn't have a valid handler type map.")

    @classmethod
    def get_data_type(cls, program: 'Program') -> 'DataType':
        data_type_manager = program.get_data_type_manager()
        is_relative = cls.is_relative(program)
        category_path = CategoryPath(CATEGORY_PATH)
        struct = get_aligned_pack4_structure(data_type_manager,
                                             category_path,
                                             cls.STRUCTURE_NAME)

        comp_dt = IntegerDataType(data_type_manager)
        struct.add(comp_dt, "nCount", None)

        if is_relative:
            comp_dt = ImageBaseOffset32DataType(data_type_manager)
            struct.add(comp_dt, "dispTypeArray", None)
        else:
            comp_dt = PointerDataType(EHCatchHandlerModel.get_data_type(program),
                                        data_type_manager)
            struct.add(comp_dt, "pTypeArray", None)

        type_def_dt = TypedefDataType(category_path,
                                       cls.DATA_TYPE_NAME,
                                       struct,
                                       data_type_manager)
        return MSDataTypeUtils.get_matching_data_type(program, type_def_dt)

    def get_data_type(self) -> 'DataType':
        if not self.data_type:
            self.data_type = EHESTypeListModel.get_data_type(self.program)
        return self.data_type

    @property
    def data_length(self):
        return self.get_data_type().get_length()

    def catch_handler_model(self) -> 'EHCatchHandlerModel':
        check_validity()
        return EHCatchHandlerModel(self.program,
                                    self.handler_type_count,
                                    self.handler_type_map_address,
                                    self.validation_options)

    @property
    def handler_type_count(self):
        if not hasattr(self, '_handler_type_count'):
            self._check_validity()
            self._handler_type_count = EHDataTypeUtilities.get_count(
                self.data_type, EHESTypeListModel.COUNT_ORDINAL, self.mem_buffer)
        return self._handler_type_count

    @property
    def handler_type_map_address(self):
        if not hasattr(self, '_handler_type_map_address'):
            self._check_validity()
            self._handler_type_map_address = EHDataTypeUtilities.get_address(
                self.data_type,
                EHESTypeListModel.TYPE_ARRAY_ORDINAL,
                self.mem_buffer)
        return get_adjusted_address(self._handler_type_map_address, self.handler_type_count)

    @property
    def component_address_of_handler_type_map_address(self):
        if not hasattr(self, '_component_address_of_handler_type_map_address'):
            self._check_validity()
            self._component_address_of_handler_type_map_address = EHDataTypeUtilities.get_component_address(
                self.data_type,
                EHESTypeListModel.TYPE_ARRAY_ORDINAL,
                self.mem_buffer)
        return self._component_address_of_handler_type_map_address
```

Note: The above Python code is a direct translation of the given Java code. However, it may not be exactly equivalent due to differences in syntax and semantics between the two languages.