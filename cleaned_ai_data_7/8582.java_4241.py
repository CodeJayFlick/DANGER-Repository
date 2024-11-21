class TypeApplierFactory:
    def __init__(self, applicator):
        self.applicator = applicator
        self.appliers_by_record_number = {}

    def get_applier_spec(self, record_number: int, expected_type) -> 'MsTypeApplier':
        applier = self.get_applier(record_number)
        if not isinstance(applier, expected_type):
            raise PdbException(f"Expected {expected_type.__name__} but got {applier.__class__.__name__}")
        return applier

    def get_applier_or_no_type_spec(self, record_number: int, expected_type) -> 'MsTypeApplier':
        applier = self.get_applier(record_number)
        if not isinstance(applier, expected_type):
            if isinstance(applier, PrimitiveTypeApplier) and applier.is_no_type():
                return applier
            raise PdbException(f"Expected {expected_type.__name__} but got {applier.__class__.__name__}")
        return applier

    def get_applier(self, record_number: int):
        if not self.appliers_by_record_number.get(record_number):
            type = self.applicator.pdb().get_type_record(record_number)
            if type is None:
                raise PdbException(f"No AbstractMsType for getTypeApplier")
            applier = self._create_applier(type)
            self.appliers_by_record_number[record_number] = applier
        return self.appliers_by_record_number.get(record_number)

    def _create_applier(self, type):
        if isinstance(type, Primitive16MsType):
            return PrimitiveTypeApplier(self.applicator, type)
        elif isinstance(type, Modifier16MsType):
            return ModifierTypeApplier(self.applicator, type)
        # ... and so on for all the other types
        else:
            raise PdbException(f"Unknown AbstractMsType {type.__class__.__name__}")

    def get_applier_type(self, type: 'AbstractMsType'):
        if isinstance(type, Primitive16MsType):
            return self._create_applier(Primitive16MsType)
        elif isinstance(type, Modifier16MsType):
            return self._create_applier(Modifier16MsType)
        # ... and so on for all the other types
        else:
            raise PdbException(f"Unknown AbstractMsType {type.__class__.__name__}")
