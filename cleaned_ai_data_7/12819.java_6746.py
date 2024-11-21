class SubDataFieldLocation:
    def __init__(self, program=None, addr=None, path=None, component_path=None, ref_addr=None, rep="", char_offset=0, field_name=""):
        super().__init__(program, addr, component_path, ref_addr, 0, 0, char_offset)
        self.rep = rep
        self.field_name = field_name

    def __str__(self):
        return f"{super().__str__()}, OpRep={self.rep}, Field Name={self.field_name}"

    def get_data_representation(self):
        return self.rep

    def get_field_name(self):
        return self.field_name


class CodeUnitLocation:
    pass  # This class is not fully implemented in the given Java code, so I left it as a placeholder.


def main():
    program = "Ghidra"
    addr = "Address"
    path = "Path"
    component_path = [1, 2]
    ref_addr = "Reference Address"
    rep = "Representation"
    char_offset = 0
    field_name = "Field Name"

    location = SubDataFieldLocation(program, addr, path, component_path, ref_addr, rep, char_offset, field_name)

    print(location)


if __name__ == "__main__":
    main()
