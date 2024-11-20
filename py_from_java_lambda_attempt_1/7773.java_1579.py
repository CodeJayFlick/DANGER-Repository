Here's your Java code translated into Python:

```Python
class EHUnwindModel:
    DATA_TYPE_NAME = "UnwindMapEntry"
    STRUCTURE_NAME = f"{DATA_TYPE_NAME}_STRUCT"

    TO_STATE_ORDINAL = 0
    ACTION_ORDINAL = 1

    def __init__(self, program: 'Program', unwind_count: int, unwind_map_address: 'Address',
                 validation_options: dict):
        super().__init__(program, unwind_count, unwind_map_address, validation_options)

    @property
    def name(self) -> str:
        return self.DATA_TYPE_NAME

    def validate_model_specific_info(self) -> None:
        program = self.get_program()
        num_entries = self.get_count()

        for i in range(num_entries):
            action_address = self.get_action_address(i)
            if action_address and not EHDataTypeUtilities.is_valid_for_function(program, action_address):
                raise InvalidDataTypeException(f"{self.name} data type at {self.get_address()} doesn't refer to a valid location for an action.")

    @staticmethod
    def get_data_type(program: 'Program') -> 'DataType':
        dt_manager = program.data_type_manager
        is_relative = EHUnwindModel.is_relative(program)
        category_path = CategoryPath("/ehdata.h/structures")
        struct_dt = MSDataTypeUtils.get_aligned_pack4_structure(dt_manager, category_path, EHUnwindModel.STRUCTURE_NAME)

        # Add the components.
        comp_dt = None

        if is_relative:
            comp_dt = ImageBaseOffset32DataType(dt_manager)
        else:
            function_def_dt = FunctionDefinitionDataType(CategoryPath("/ehdata.h/structures"), "action", dt_manager)
            function_def_dt.set_return_type(VoidDataType(dt_manager))
            comp_dt = PointerDataType(function_def_dt, dt_manager)

        struct_dt.add(comp_dt, "action", None)

        typedef_dt = TypedefDataType(category_path, EHUnwindModel.DATA_TYPE_NAME, struct_dt, dt_manager)
        return MSDataTypeUtils.get_matching_data_type(program, typedef_dt)

    def get_data_type(self) -> 'DataType':
        if not self.data_type:
            self.data_type = self.get_data_type(self.get_program())
        return self.data_type

    @property
    def data_length(self) -> int:
        return self.get_data_type().get_length()

    def get_to_state(self, unwind_ordinal: int) -> int:
        if not 0 <= unwind_ordinal < self.get_count():
            raise InvalidDataTypeException("Invalid UnwindMapEntry ordinal")

        dt = self.get_data_type()
        specific_mem_buffer = self.get_specific_mem_buffer(unwind_ordinal, dt)
        return EHDataTypeUtilities.get_eh_state_value(dt, EHUnwindModel.TO_STATE_ORDINAL, specific_mem_buffer)

    def get_action_address(self, unwind_ordinal: int) -> 'Address':
        if not 0 <= unwind_ordinal < self.get_count():
            raise InvalidDataTypeException("Invalid UnwindMapEntry ordinal")

        dt = self.get_data_type()
        specific_mem_buffer = self.get_specific_mem_buffer(unwind_ordinal, dt)
        return EHDataTypeUtilities.get_address(dt, EHUnwindModel.ACTION_ORDINAL, specific_mem_buffer)

    def get_component_address_of_action_address(self, unwind_ordinal: int) -> 'Address':
        if not 0 <= unwind_ordinal < self.get_count():
            raise InvalidDataTypeException("Invalid UnwindMapEntry ordinal")

        dt = self.get_data_type()
        specific_mem_buffer = self.get_specific_mem_buffer(unwind_ordinal, dt)
        return EHDataTypeUtilities.get_component_address(dt, EHUnwindModel.ACTION_ORDINAL, specific_mem_buffer)

    @staticmethod
    def is_relative(program: 'Program') -> bool:
        # TO DO: implement this method.
        pass

class InvalidDataTypeException(Exception):
    pass
```

Note that I've used Python's type hinting feature to indicate the expected types of variables and function parameters. This can help catch errors at runtime, but it is not enforced by Python itself.

Also note that some methods are marked as `@staticmethod`, which means they belong to the class rather than instances of the class.