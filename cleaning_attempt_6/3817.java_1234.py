class CreateEquateCmd:
    def __init__(self, scalar, iterator=None, enoom=None, overwrite_existing=False, context=None):
        self.target_scalar_value = scalar.value
        self.iterator = iterator
        self.equate_name = None
        self.overwrite_existing = overwrite_existing
        self.context = context
        if enoom is not None:
            self.enoom = enoom

    def apply_to(self, domain, monitor=None):
        if monitor is not None:
            monitor.set_indeterminate(True)
            monitor.set_message("Creating Equate")

        while iterator.has_next() and not monitor.is_cancelled():
            code_unit = next(iterator)
            if isinstance(code_unit, Instruction):
                self.maybe_create_equate(domain, code_unit)
            elif isinstance(code_unit, Data):
                self.maybe_create_equate(domain, code_unit)

    def maybe_create_equate(self, domain, data):
        if not data.is_defined():
            return

        value = data.get_value()
        if not isinstance(value, Scalar) or value.value != self.target_scalar_value:
            return

        op_index = self.get_operand_index()
        self.create_equate(domain, data, op_index)

    def maybe_create_equate(self, domain, instruction):
        for i in range(instruction.num_operands()):
            ops = instruction.get_op_objects(i)
            for op in ops:
                if isinstance(op, Scalar) and op.value == self.target_scalar_value:
                    self.create_equate(domain, instruction, i)

    def create_equate(self, domain, code_unit, op_index):
        equate_table = code_unit.program().get_equate_table()
        address = code_unit.get_address()

        cur_equate = equate_table.get_equate(address, op_index)
        if self.equate_name is None and self.enoom:
            self.equate_name = generate_formatted_equate_name(self.context)

        if cur_equate is None or not overwrite_existing:
            cmd = SetEquateCmd(self.equate_name, address, op_index) if self.equate_name else RenameEquateCmd(cur_equate.name(), self.equate_name, address)
            cmd.apply_to(domain)
        elif overwrite_existing and cur_equate:
            cmd = RenameEquateCmd(cur_equate.name(), self.equate_name, address)
            cmd.apply_to(domain)

    def generate_formatted_equate_name(self):
        program = self.context.get_program()
        enum_with_id = program.data_type_manager().add_data_type(self.enoom, None)
        formatted_name = EquateManager.format_name_for_equate(enum_with_id.universal_id(), self.target_scalar_value)
        return formatted_name

    def get_operand_index(self):
        location = self.context.location
        if isinstance(location, OperandFieldLocation):
            return location.operand_index()
        else:
            return -1


class SetEquateCmd:
    pass  # This class is not implemented in the given Java code.


class RenameEquateCmd:
    pass  # This class is not implemented in the given Java code.
