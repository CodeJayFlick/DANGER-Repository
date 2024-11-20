Here is the translation of the Java code into Python:

```Python
class PointerTypeApplier:
    def __init__(self, applicator: 'PdbApplicator', ms_type: 'AbstractPointerMsType') -> None:
        self.applicator = applicator
        self.ms_type = ms_type

    @property
    def is_function_pointer(self) -> bool:
        return self._is_function_pointer

    @_is_function_pointer.setter
    def is_function_pointer(self, value: bool) -> None:
        self._is_function_pointer = value

    def get_size(self) -> int:
        size = (self.ms_type).get_size()
        if isinstance(size, int):
            return size
        else:
            raise ValueError("Size must be an integer")

    def apply(self) -> 'DataType':
        if isinstance(self.ms_type, DummyMsType):
            data_type = PointerDataType(underlying_type=self.applicator.get_data_type_manager())
        else:
            data_type = self.apply_abstract_pointer_ms_type(ms_type=self.ms_type)
        return data_type

    def resolve(self) -> None:
        pass  # Do not resolve pointer types... will be resolved naturally, as needed

    def get_unmodified_underlying_type_applier(self) -> 'MsTypeApplier':
        underlying_type_applier = self.applicator.get_type_applier(
            record_number=self.ms_type.get_underlying_record_number())
        if isinstance(underlying_type_applier, ModifierTypeApplier):
            modifier_type_applier = underlying_type_applier
            modified_record_number = (
                (modifier_type_applier.get_ms_type())).get_modified_record_number()
            underlying_type_applier = self.applicator.get_type_applier(
                record_number=modified_record_number)
        return underlying_type_applier

    def apply_abstract_pointer_ms_type(self, ms_type: 'AbstractPointerMsType') -> 'DataType':
        underlying_type_applier = self.applicator.get_type_applier(
            record_number=ms_type.get_underlying_record_number())
        if isinstance(underlying_type_applier, ProcedureTypeApplier):
            self.is_function_pointer = True
        else:
            self.is_function_pointer = False

        underlying_type = underlying_type_applier.get_cycle_break_type()
        if underlying_type is None:
            # TODO: we have seen underlyingTypeApplier is for NoTypeApplier for VtShapeMsType
            #  Figure it out, and perhaps create an applier that creates a structure or something?
            underlying_type = self.applicator.get_pdb_primitive_type_applicator().get_void_type()
            self.applicator.append_log_msg(
                f"PDB Warning: No type conversion for {underlying_type_applier.get_ms_type()} as underlying type for pointer. Using void.")
        size = ms_type.get_size().value
        if size == self.applicator.data_organization.pointer_size:
            size = -1  # Use default

        return PointerDataType(
            underlying_type=underlying_type,
            size=size,
            data_type_manager=self.applicator.get_data_type_manager())
```

Please note that this is a direct translation of the Java code into Python, and it may not be perfect. The original Java code might have some dependencies or imports which are missing in this Python version.