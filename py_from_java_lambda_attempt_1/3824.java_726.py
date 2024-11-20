Here is the translation of the given Java code into Python:

```Python
class RenameEquateCmd:
    def __init__(self, old_equate_name=None, new_equate_name=None, addr=None, op_index=None):
        self.old_equate_name = old_equate_name
        self.new_equate_name = new_equate_name
        self.addr = addr
        self.op_index = op_index

    @property
    def name(self):
        return "Rename Equate"

    def apply_to(self, program):
        equate_table = program.get_equate_table()

        # First make sure there's an entry in the equates table for the equate to be changed (there should always be one).
        from_equate = equate_table.get_equate(self.old_equate_name)
        if from_equate is None:
            return False, "Equate not found: {}".format(self.old_equate_name)

        # Get the value behind the equate...for later use.
        value = from_equate.get_value()

        # See if there are 0 references to this equate. If so, remove it from the table.
        if from_equate.get_reference_count() <= 1:
            equate_table.remove_equate(self.old_equate_name)
        else:  # Otherwise, there's at least one ref, so remove it.
            from_equate.remove_reference(self.addr, self.op_index)

        # If the new name is null, then this is an enum equate and we need to add the enum to the data type manager to generate the correct new formatted equate name.
        if self.new_equate_name is None:
            enoom = program.get_data_type_manager().add_data_type(self.enoom)
            self.new_equate_name = EquateManager.format_name_for_equate(enoom.get_universal_id(), value)

        # Now move the ref to the new equate name. To do this, first check the table
        # to see if an entry already exists for this name; if so, use it. If not, create one.
        to_equate = equate_table.get_equate(self.new_equate_name)
        if to_equate is None:
            try:
                to_equate = equate_table.create_equate(self.new_equate_name, value)
            except (DuplicateNameException, InvalidInputException) as e:
                return False, "Invalid equate name: {}".format(self.new_equate_name)

        # Add the reference.
        to_equate.add_reference(self.addr, self.op_index)
        return True, None

    @property
    def status_msg(self):
        if hasattr(self, 'msg'):
            return self.msg
        else:
            return None


# Example usage:

rename_cmd = RenameEquateCmd(old_equate_name='old_equate', new_equate_name=None, addr=0x1234, op_index=1)
program = Program()  # Assuming you have a program object.
success, msg = rename_cmd.apply_to(program)

if not success:
    print(msg)