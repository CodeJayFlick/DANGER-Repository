class DisplayableVariableOffset:
    def __init__(self, function: 'Function', parameter_address):
        self.function = function
        self.parameter_address = parameter_address
        if parameter_address is not None:
            self.offset = parameter_address.get_offset()
            self.offset_as_big_integer = parameter_address.get_offset_as_big_integer()
        else:
            self.offset = 0
            self.offset_as_big_integer = None

    def get_address(self):
        return self.parameter_address

    def get_offset(self):
        return self.offset

    def get_offset_as_big_integer(self):
        return self.offset_as_big_integer

    def get_display_string(self):
        if self.parameter_address is None or self.parameter_address == 'NO_ADDRESS':
            return 'NO OFFSET'
        else:
            return str(self.parameter_address)

    def __str__(self):
        return self.get_display_string()

    def compare_to(self, other_displayable_offset: 'DisplayableVariableOffset'):
        if other_displayable_offset is None:
            return 1
        other_address = other_displayable_offset.get_address()
        if self.parameter_address is None:
            if other_address is not None:
                return -1
            else:
                return 0
        elif other_address is None:
            return 1
        else:
            return self.parameter_address.compare_to(other_address)
