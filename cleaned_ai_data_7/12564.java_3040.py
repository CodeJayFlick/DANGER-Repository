class OperandRepresentationList(list):
    def __init__(self, op_list=None, primary_reference_is_hidden=False, has_error=False):
        super().__init__()
        self.primary_reference_is_hidden = primary_reference_is_hidden
        self.has_error = has_error

        if op_list is not None:
            self.extend(op_list)

    @property
    def primary_reference_hidden(self):
        return self.primary_reference_is_hidden

    @primary_reference_hidden.setter
    def primary_reference_hidden(self, value):
        self.primary_reference_is_hidden = value

    @property
    def has_error_value(self):
        return self.has_error

    @has_error_value.setter
    def has_error_value(self, value):
        self.has_error = value

    def __str__(self):
        result = ""
        for op_elem in self:
            if isinstance(op_elem, str) and self.has_error:
                result += f"Error: {op_elem}\n"
            else:
                result += str(op_elem)
        return result
