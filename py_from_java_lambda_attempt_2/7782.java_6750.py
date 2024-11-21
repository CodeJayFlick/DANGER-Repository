Here is the translation of the Java code into Python:

```Python
class Rtti3Model:
    DATA_TYPE_NAME = "RTTIClassHierarchyDescriptor"
    STRUCTURE_NAME = "_s__" + DATA_TYPE_NAME
    
    SIGNATURE_ORDINAL = 0
    ATTRIBUTES_ORDINAL = 1
    BASE_ARRAY_PTR_ORDINAL = 3

    NUM_BASES_OFFSET = 8
    BASE_ARRAY_PTR_OFFSET = 12
    MAX_RTTI_1_COUNT = 1000

    def __init__(self, program: 'Program', rtti3_address: 'Address',
                 validation_options: 'DataValidationOptions'):
        super().__init__(program, rtti3_address, validation_options)

    @property
    def name(self):
        return self.DATA_TYPE_NAME

    def validate_model_specific_info(self) -> None:
        program = self.get_program()
        
        # Num1 is dword at SIGNATURE_OFFSET.
        # No additional validation for this yet.

        # Num2 is dword at ATTRIBUTES_ OFFSET.
        # No additional validation for this yet.

        rtti1_count = self.get_rtti1_count()
        if not 1 <= rtti1_count <= MAX_RTTI_1_COUNT:
            raise InvalidDataTypeException(f"Invalid RTTI1 count: {rtti1_count}")

        validate_referred_to_data = validation_options.should_validate_referred_to_data()

        # Last component should refer to RTTI2.
        rtti2_address = self.get_rtti2_address()
        if not isinstance(rtti2_address, 'Address'):
            raise InvalidDataTypeException(f"Invalid location for the {Rtti2Model.DATA_TYPE_NAME}.")

        self.rtti2_model = Rtti2Model(self.get_program(), rtti1_count, rtti2_address,
                                       validation_options)
        if validate_referred_to_data:
            self.rtti2_model.validate()
        else:
            if not self.rtti2_model.is_loaded_and_initialized_address():
                raise InvalidDataTypeException(f"Data referencing {self.rtti2_model.name} isn't a loaded and initialized address.")

    @classmethod
    def get_data_type(cls, program: 'Program') -> 'DataType':
        rtti3_dt = cls.get_simple_data_type(program)
        rtti1_dt = Rtti1Model.get_simple_data_type(program)

        # Now make each refer to the other.
        set_rtti1_data_type(rtti3_dt, program, rtti1_dt)
        Rtti1Model.set_rtti3_data_type(rtti1_dt, program, rtti3_dt)

        return MSDataTypeUtils.get_matching_data_type(program, rtti3_dt)

    @classmethod
    def get_simple_data_type(cls, program: 'Program') -> 'DataType':
        category_path = CategoryPath()
        struct = cls._get_aligned_pack4_structure(program.data_type_manager,
                                                   category_path,
                                                   Rtti3Model.STRUCTURE_NAME)
        
        # Add the components.
        d_word_dt = DWordDataType(program.data_type_manager)
        struct.add(d_word_dt, "signature", None)
        struct.add(d_word_dt, "attributes", "bit flags")
        struct.add(d_word_dt, "numBaseClasses", "number of base classes (i.e. rtti1Count)")

        if MSDataTypeUtils.is_64_bit(program):
            rtti2_ref_dt = ImageBaseOffset32DataType(program.data_type_manager)
        else:
            rtti2_ref_dt = PointerDataType(Rtti2Model.get_simple_individual_entry_data_type(program))

        struct.add(rtti2_ref_dt, "pBaseClassArray", "ref to BaseClassArray (RTTI 2)")

        return TypedefDataType(category_path,
                                 Rtti3Model.DATA_TYPE_NAME,
                                 struct,
                                 program.data_type_manager)

    def get_data_type(self) -> 'DataType':
        if self.data_type is None:
            self.data_type = cls.get_data_type(self.get_program())
        return self.data_type

    @property
    def data_length(self):
        return self.get_data_type().get_length()

    def get_signature(self) -> int:
        check_validity()
        return EHDataTypeUtilities.get_integer_value(self.get_data_type(),
                                                       Rtti3Model.SIGNATURE_ORDINAL,
                                                       self.mem_buffer)

    def get_attributes(self) -> int:
        check_validity()
        return EHDataTypeUtilities.get_integer_value(self.get_data_type(),
                                                       Rtti3Model.ATTRIBUTES_ORDINAL,
                                                       self.mem_buffer)

    @classmethod
    def get_rtti1_count(cls, program: 'Program', rtti3_address: 'Address') -> int:
        memory = program.memory

        rtti1_count_address = rtti3_address.add(Rtti3Model.NUM_BASES_OFFSET)
        return (int)(Scalar(32, memory.get_int(rtti1_count_address,
                                                  memory.is_big_endian())).get_value())

    def get_rtti2_address(self) -> 'Address':
        check_validity()
        return self._get_rtti2_address(self.get_program(), self.address)

    @classmethod
    def _get_rtti2_address(cls, program: 'Program', rtti3_address: 'Address') -> 'Address':
        memory = program.memory

        rtti2_comp_address = rtti3_address.add(Rtti3Model.BASE_ARRAY_PTR_OFFSET)
        pointed_to_address = get_referenced_address(program, rtti2_comp_address)

        if not isinstance(pointed_to_address, 'Address'):
            return None
        elif not memory.contains(pointed_to_address):
            return None

        return pointed_to_address

    def refers_to_rtti0(self, rtti0_address: 'Address') -> bool:
        try:
            check_validity()
            return self.rtti2_model.refers_to_rtti0(rtti0_address)
        except InvalidDataTypeException as e:
            return False

    @property
    def base_class_types(self) -> List[str]:
        check_validity()
        return self.rtti2_model.base_class_types

    @property
    def rtti0_model(self) -> 'TypeDescriptorModel':
        check_validity()
        return self.rtti2_model.rtti0_model

    @property
    def rtti2_model(self) -> 'Rtti2Model':
        check_validity()
        return self.rtti2_model
```

Note that this translation is not perfect, as some Java-specific concepts (like `static` methods and variables) do not have direct equivalents in Python.