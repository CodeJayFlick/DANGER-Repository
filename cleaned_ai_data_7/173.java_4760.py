class EnumPcodeRow:
    def __init__(self, message):
        self.message = f"({message})"

    def get_sequence(self):
        return 0

    def get_code(self):
        return self.message

    def get_op(self):
        return None


pcode_row_types = ["no thread selected", "decode instruction"]

for pcode_row_type in pcode_row_types:
    enum_pcode_row = EnumPcodeRow(pcode_row_type)
    print(f"EnumPcodeRow: {enum_pcode_row.get_code()}")
