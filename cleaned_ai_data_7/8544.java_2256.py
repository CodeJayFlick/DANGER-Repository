class EnumTypeApplier:
    def __init__(self, applicator: 'PdbApplicator', ms_type: 'AbstractEnumMsType'):
        super().__init__(applicator, ms_type)

    @property
    def size(self) -> int | None:
        underlying_applier = self.get_underlying_type_applier()
        if underlying_applier is not None:
            return underlying_applier.size
        else:
            return 0

    @property
    def length(self) -> int:
        # Minimum length allowed by Ghidra is 1 for enum, so all returns are min 1.
        underlying_applier = self.get_underlying_type_applier()
        if underlying_applier is not None:
            data_type = underlying_applier.data_type
            return max(data_type.length, 1)
        else:
            return 1

    def is_signed(self) -> bool:
        underlying_applier = self.get_underlying_type_applier()
        if underlying_applier is not None:
            data_type = underlying_applier.data_type
            if isinstance(data_type, AbstractIntegerDataType):
                return data_type.is_signed
            else:
                return False

    def get_dependency_applier(self) -> 'EnumTypeApplier':
        if self.definition_applier and isinstance(self.definition_applier, EnumTypeApplier):
            return self.definition_applier
        return self

    @property
    def name(self) -> str:
        return self.ms_type.name

    def create_empty_enum(self, ms_type: 'AbstractEnumMsType') -> 'EnumDataType':
        category_path = applicator.category(applicator.fixed_symbol_path.parent)
        enum_data_type = EnumDataType(category_path, applicator.fixed_symbol_path.name,
                                       self.length, applicator.data_type_manager)

        return enum_data_type

    def apply(self) -> None:
        get_or_create_enum()

        abstract_enum_ms_type = ms_type
        if not is_forward_reference():
            super().apply()
        else:
            apply_enum_ms_type(abstract_enum_ms_type)

    @property
    def forward_reference_applier(self):
        return self.definition_applier

    def resolve(self) -> None:
        if not is_forward_reference():
            super().resolve()

    def get_or_create_enum(self) -> None:
        abstract_enum_ms_type = ms_type
        if data_type is not None or is_forward_reference():
            return
        else:
            needed_type = (AbstractEnumMsType) ms_type
            if definition_applier and isinstance(definition_applier, EnumTypeApplier):
                data_type = definition_applier.data_type_internal()
                if data_type is not None:
                    return

    def apply_enum_ms_type(self, abstract_enum_ms_type: 'AbstractEnumMsType') -> 'EnumDataType':
        field_list_record_number = ms_type.field_descriptor_list_record_number
        field_list_applier = FieldListTypeApplier.get_field_list_applier_special(applicator,
                                                                                  field_list_record_number)

        member_list = field_list_applier.member_list

        num_elements = abstract_enum_ms_type.num_elements
        if len(member_list) != num_elements:
            pdb_log_and_info_message(self, f"Enum expecting {num_elements} elements, but only "
                                             f"{len(member_list)} available for {ms_type.name}")

    def narrowing_conversion(self, output_size: int | None, is_signed: bool,
                              numeric: 'Numeric') -> int | None:
        if not isinstance(numeric, Integral):
            return 0
