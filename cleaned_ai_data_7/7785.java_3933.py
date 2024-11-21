class VfTableModel:
    DATA_TYPE_NAME = "vftable"
    NO_LAST_COUNT = -1

    def __init__(self, program: 'Program', vf_table_address: 'Address',
                 validation_options):
        super().__init__(program=program, count=1,
                         address=vf_table_address,
                         validation_options=validation_options)
        self.element_count = RttiUtil.get_vf_table_count(program, vf_table_address)

    def get_element_count(self) -> int:
        return self.element_count

    @property
    def name(self):
        return self.DATA_TYPE_NAME

    def validate_model_specific_info(self):
        program = self.program
        start_address = self.address

        meta_address = self.meta_address
        rtti4_address = get_absolute_address(program, meta_address)
        self.rtti4_model = Rtti4Model(program=program,
                                       address=rtti4_address,
                                       validation_options=self.validation_options)

        individual_entry_data_type = PointerDataType()
        entry_size = individual_entry_entry_data_type.length

        num_entries = self.element_count
        if num_entries == 0:
            raise InvalidDataTypeException(
                f"{self.name} data type at {start_address} doesn't have a valid vf table.")

        vf_table_field_address = start_address
        for ordinal in range(num_entries):
            function_address = get_absolute_address(program, vf_table_field_address)
            if function_address is None:
                raise InvalidDataTypeException(
                    f"{self.name} at {start_address} doesn't refer to a valid function.")
            try:
                vf_table_field_address += entry_size
            except AddressOutOfBoundsException as e:
                if ordinal < (num_entries - 1):
                    raise InvalidDataTypeException(
                        f"{self.name} at {start_address} isn't valid.")
                break

    def get_data_type(self, program: 'Program') -> 'DataType':
        if self.last_program != program or self.last_element_count == VfTableModel.NO_LAST_COUNT:
            self.is_data_type_already_based_on_count = True
            self.last_program = program
            self.last_data_type = None
            self.last_element_count = self.element_count

            if self.last_element_count > 0:
                data_manager = program.data_type_manager
                pointer_dt = PointerDataType(data_manager)
                array_dt = ArrayDataType(pointer_dt, self.last_element_count,
                                           pointer_dt.length, data_manager)

                self.last_data_type = MSDataUtils.get_matching_data_type(program, array_dt)
            else:
                self.last_data_type = None

        return self.last_data_type

    @property
    def data_type(self) -> 'DataType':
        if not hasattr(self, "data_type"):
            self.data_type = self.get_data_type(self.program)

        return self.data_type

    @property
    def default_pointer_size(self):
        # This method is missing in the original Java code.
        pass

    def get_virtual_function_pointer(self, table_element_index: int) -> 'Address':
        address = self.address + (self.default_pointer_size * table_element_index)
        return get_absolute_address(self.program, address)

    @property
    def rtti0_model(self):
        if not hasattr(self, "rtti4_model"):
            check_validity()
        return self.rtti4_model.get_rtti0_model()

    @property
    def meta_address(self) -> 'Address':
        return self.address - self.program.default_pointer_size

class Rtti4Model:
    pass  # This class is missing in the original Java code.

def get_absolute_address(program: 'Program', address: 'Address') -> 'Address':
    pass  # This method is missing in the original Java code.
