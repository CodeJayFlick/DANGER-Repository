class PcodeFieldLocation:
    def __init__(self, program, addr, pcode_strings, row, char_offset):
        super().__init__(program, addr, row, 0, char_offset)
        self.pcode_strings = pcode_strings

    def get_pcode_strings(self):
        return tuple(self.pcode_strings)

    def save_state(self, obj):
        super().save_state(obj)
        obj.put("_PCODE_STRINGS", tuple(self.pcode_strings))

    def restore_state(self, program, obj):
        super().restore_state(program, obj)
        strings = obj.get("._PCODE_STRINGS")
        self.pcode_strings = list(strings)

    def __str__(self):
        return f"{super().__str__()}, Pcode sample: {self.get_pcode_sample()}"

    def get_pcode_sample(self):
        if not self.pcode_strings:
            return "<no pcode>"
        return self.pcode_strings[0]
