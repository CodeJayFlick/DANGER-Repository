class RangeAttribute:
    def __init__(self):
        self.attributes = None
        self.may_have_no_user_name_on_a_control_flow_path = False

    def from_pdb_reader(self, reader):
        try:
            self.attributes = reader.parse_unsigned_short_val()
            self.process_attributes(self.attributes)
        except Exception as e:
            print(f"PDBException: {str(e)}")

    def emit(self):
        builder = ""
        if self.may_have_no_user_name_on_a_control_flow_path:
            builder += "MayAvailable"
        else:
            builder += ""

        return f"Attributes: {builder}"

    def process_attributes(self, val):
        self.may_have_no_user_name_on_a_control_flow_path = (val & 0x0001) == 0x0001
