class StartInstructionValue:
    def __init__(self, location):
        super().__init__(location)

    def get_value(self, pos):
        return (pos.get_addr().get_offset() >> pos.get_addr().get_space().get_scale())

    def gen_min_pattern(self, ops):
        return TokenPattern(self.location)

    def gen_pattern(self, val):
        return TokenPattern(self.location)

    def min_value(self):
        return 0

    def max_value(self):
        return 0

    def save_xml(self, s):
        s.write("<start_exp/>")

    def restore_xml(self, el, trans):
        pass


class Location:
    # This class is not implemented in the original Java code
    pass


class TokenPattern:
    # This class is not implemented in the original Java code
    pass


# Usage example:

location = "some_location"
start_instruction_value = StartInstructionValue(location)
pos = {"get_addr": lambda: {"get_offset": 0, "get_space": {"get_scale": 1}}}
print(start_instruction_value.get_value(pos))
