Here is the translation of the Java code into Python:

```Python
class Rtti1Model:
    DATA_TYPE_NAME = "RTTIBaseClassDescriptor"
    STRUCTURE_NAME = "_s_" + DATA_TYPE_NAME
    
    NUM_BASES_ORDINAL = 1
    MEMBER_DISP_ORDINAL = 2
    ATTRIBUTES_ORDINAL = 3
    CLASS_HIERARCHY_POINTER_ORDINAL = 4

    TYPE_DESC_POINTER_OFFSET = 0
    NUM_BASES_OFFSET = 4
    CLASS_HIERARCHY_POINTER_OFFSET = 24
    
    MDISP_ORDINAL = 0
    PDISP_ORDINAL = 1
    VDISP_ORDINAL = 2

    def __init__(self, program: Program, rtti1_address: Address,
                 validation_options: DataValidationOptions):
        super().__init__(program, 1, rtti1_address, validation_options)

    @property
    def name(self) -> str:
        return self.DATA_TYPE_NAME

    def validate_model_specific_info(self) -> None:
        program = self.get_program()
        memory = program.memory
        start_address = self.get_address()

        try:
            # Test that we can get the expected number of bytes.
            memory.get_bytes(start_address, 24)

            if validation_options.should_validate_referred_to_data():
                rtti0_model = TypeDescriptorModel(self.get_rtti0_address(), program)
                rtti0_model.validate()
            else:
                self.check_loaded_and_initialized_address(rtti0_model)

        except (MemoryAccessException | AddressOutOfBoundsException) as e:
            self.invalid(e)

    @staticmethod
    def get_data_type(program: Program, validation_options: DataValidationOptions = None):
        # Create simple data types for RTTI 1 & RTTI 3.
        rtti1_dt = Rtti1Model.get_simple_data_type(program)
        if validation_options:
            set_rtti3_data_type(rtti1_dt, program)

    @staticmethod
    def get_simple_data_type(program: Program):
        # Create simple data types for RTTI 1 & RTTI 3.
        category_path = CategoryPath(CATEGORY_PATH)
        structure = StructureDataType(category_path, STRUCTURE_NAME)

        rtti0_ref_dt = PointerDataType(TypeDescriptorModel.get_data_type(program))
        rtti3_ref_dt = PointerDataType()

        d_word_data_type = DWordDataType()
        pmd_data_type = MSDataTypeUtils.get_pmd_data_type(program)
        structure.add(rtti0_ref_dt, "pTypeDescriptor", "ref to TypeDescriptor (RTTI 0) for class")
        structure.add(d_word_data_type, "numContainedBases",
                      "count of extended classes in BaseClassArray (RTTI 2)")
        structure.add(pmd_data_type, "where", "member displacement structure")
        structure.add(d_word_data_type, "attributes", "bit flags")
        structure.add(rtti3_ref_dt, "pClassHierarchyDescriptor",
                     "ref to ClassHierarchyDescriptor (RTTI 3) for class")

        return TypedefDataType(category_path, DATA_TYPE_NAME, structure)

    def get_address(self):
        # This method is not implemented in the Java code.
        pass

    @property
    def data_type(self):
        if self._data_type is None:
            self._data_type = Rtti1Model.get_data_type(self.get_program())
        return self._data_type

    @property
    def rtti0_model(self) -> TypeDescriptorModel | None:
        try:
            check_validity()
        except InvalidDataTypeException as e:
            return None
        return self._rtti0_model

    @property
    def rtti3_model(self) -> Rtti3Model | None:
        try:
            check_validity()
        except InvalidDataTypeException as e:
            return None
        return self._rtti3_model

class Program:  # This class is not implemented in the Java code.
    pass

class Address:  # This class is not implemented in the Java code.
    pass

class DataValidationOptions:  # This class is not implemented in the Java code.
    def should_validate_referred_to_data(self) -> bool:
        return True
```

Note that this translation assumes a Python version of at least 3.6, as it uses type hints and f-strings for formatting strings.