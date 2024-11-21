class EditReferencesModel:
    OPERAND = "Operand"
    LOCATION = "Destination"
    LABEL = "Label"
    REF_TYPE = "Ref-Type"
    IS_PRIMARY = "Primary?"
    REF_SOURCE = "Source"

    DEFAULT_SORT_COL = 0

    COLUMN_NAMES = [OPERAND, LOCATION, LABEL, REF_TYPE, IS_PRIMARY, REF_SOURCE]
    COLUMN_CLASSES = [str, AddressBasedLocation, str, type(None), bool, type(None)]

    def __init__(self, plugin):
        self.plugin = plugin
        self.cuFormat = plugin.get_code_unit_format()
        self.refs = []

    def set_code_unit_location(self, cu):
        if cu is None:
            self.refs = []
        else:
            self.refs = cu.references_from()
        self.fire_table_data_changed()

    @property
    def program(self):
        return self.cu.program if self.cu else None

    def get_name(self):
        return "Edit References"

    def get_column_count(self):
        return len(COLUMN_NAMES)

    def get_row_count(self):
        return len(self.refs)

    def get_column_class(self, column_index):
        return COLUMN_CLASSES[column_index]

    def is_cell_editable(self, row_index, column_index):
        if column_index == self.IS_PRIMARY_COL or column_index == self.REF_TYPE_COL:
            if row_index >= len(self.refs):
                return False
            to_addr = self.refs[row_index].to_address()
            if to_addr.is_memory_address():
                return True
            if column_index == self.REF_TYPE_COL:
                return True

    def get_column_value_for_row(self, reference, column_index):
        switcher = {
            0: lambda: f"OP-{reference.operand_index}",
            1: lambda: AddressBasedLocation(self.program, reference, cuFormat.show_block_name),
            2: lambda: self.get_to_label(reference),
            3: lambda: reference.reference_type,
            4: lambda: bool(reference.is_primary()),
            5: lambda: reference.source
        }
        return switcher.get(column_index)()

    def get_model_data(self):
        return [self.refs]

    def set_value_at(self, value, row_index, column_index):
        if row_index >= len(self.refs):
            return

        ref = self.refs[row_index]
        switcher = {
            3: lambda v: Command(EditRefTypeCmd(ref, RefType(v)), self.plugin.get_tool(), cu=self.cu.program),
            4: lambda v: Command(SetPrimaryRefCmd(ref, bool(v)), self.plugin.get_tool(), cu=self.cu.program)
        }
        if column_index in switcher:
            cmd = switcher[column_index](value)
            self.plugin.get_tool().execute(cmd)

    def get_to_label(self, reference):
        return cuFormat.reference_representation_string(cu=reference.from_address) if cu else None

    def get_column_name(self, column_index):
        return COLUMN_NAMES[column_index]

    def get_row(self, ref):
        for row in range(len(self.refs)):
            if self.refs[row] == ref:
                return row
        return -1

    def get_reference(self, row):
        return self.refs[row] if row < len(self.refs) else None

    @staticmethod
    def allowed_ref_types(program, reference):
        to_addr = reference.to_address()
        if to_addr.is_stack_address():
            return RefTypeFactory.stack_ref_types
        elif to_addr.is_register_address():
            return RefTypeFactory.data_ref_types
        elif to_addr.is_memory_address():
            if program.address_factory.default_address_space == to_addr.get_address_space() or is_computed_flow(program, reference):
                return RefTypeFactory.memory_ref_types
            else:
                return RefTypeFactory.data_ref_types
        elif to_addr.is_external_address():
            return RefTypeFactory.external_ref_types

    @staticmethod
    def is_computed_flow(program, ref):
        instr = program.listing.get_instruction_at(ref.from_address)
        return instr and instr.flow_type.is_computed
