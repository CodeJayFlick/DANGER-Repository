class StackFrameImpl:
    def __init__(self, function):
        self.function = function
        self.grows_negative = function.get_program().get_compiler_spec().stack_grows_negative()
        base_offset = VariableUtilities.get_base_stack_param_offset(function)
        if base_offset is not None:
            self.param_start = int(base_offset.value())
        else:
            self.param_start = UNKNOWN_PARAM_OFFSET

    def variable_changed(self, stack_var):
        raise UnsupportedOperationException()

    def create_variable(self, name, offset, data_type, source_type):
        raise UnsupportedOperationException()

    @property
    def locals(self):
        if self.get_parameter_offset() >= 0:
            return self.get_negative_variables()
        else:
            return self.get_positive_variables()

    @property
    def parameters(self):
        return (self.get_parameter_offset() >= 0) and self.get_positive_variables() or self.get_negative_variables()

    @property
    def frame_size(self):
        size = self.get_local_size()
        if self.grows_negative:
            size += self.get_positive_size()
        else:
            size -= self.get_negative_size()
        return size

    @property
    def local_size(self):
        if self.local_size > 0:
            return self.local_size
        elif self.grows_negative:
            return self.get_negative_size()
        else:
            return self.get_positive_size()

    @local_size.setter
    def set_local_size(self, value):
        raise UnsupportedOperationException()

    @property
    def grows_negative(self):
        return self.grows_negative

    @property
    def parameter_offset(self):
        return self.param_start

    @parameter_offset.setter
    def set_parameter_offset(self, offset):
        pass  # Not implemented in Python version

    @property
    def return_address_offset(self):
        return self.return_start

    @return_address_offset.setter
    def set_return_address_offset(self, value):
        raise UnsupportedOperationException()

    def get_variable_containing(self, offset):
        key = int(offset)
        index = bisect.bisect_left(self.variables, key) - 1
        if index >= 0:
            return self.variables[index]
        else:
            var = None
            for i in range(index + 1):
                var = self.variables[i]
                stack_offset = var.stack_offset()
                if (stack_offset + var.length()) > offset and not var.data_type.is_deleted():
                    break
            return var

    def get_negative_size(self):
        param_start = self.get_parameter_offset()
        if len(self.variables) == 0:
            return -param_start
        else:
            start = self.variables[0].stack_offset()
            if start >= 0 or start > param_start:
                break
            for i in range(len(self.variables)):
                var = self.variables[i]
                stack_offset = var.stack_offset()
                if (stack_offset + var.length()) > offset and not var.data_type.is_deleted():
                    return -start

    def get_positive_size(self):
        param_start = self.get_parameter_offset()
        if len(self.variables) == 0:
            return param_start
        else:
            start = self.variables[-1].stack_offset()
            for i in range(len(self.variables)):
                var = self.variables[i]
                stack_offset = var.stack_offset()
                if (stack_offset + var.length()) > offset and not var.data_type.is_deleted():
                    break
            return start

    def get_negative_variables(self):
        if len(self.variables) == 0:
            return []
        else:
            for i in range(len(self.variables)):
                var = self.variables[i]
                stack_offset = var.stack_offset()
                if (stack_offset + var.length()) > offset and not var.data_type.is_deleted():
                    break
            return self.variables[:i]

    def get_positive_variables(self):
        if len(self.variables) == 0:
            return []
        else:
            for i in range(len(self.variables)):
                var = self.variables[i]
                stack_offset = var.stack_offset()
                if (stack_offset + var.length()) > offset and not var.data_type.is_deleted():
                    break
            return self.variables[i:]

    def get_parameter_count(self):
        if self.grows_negative:
            return len(self.get_positive_variables())
        else:
            return -len(self.get_negative_variables())

    @property
    def function(self):
        return self.function

class Variable:
    pass  # Not implemented in Python version

UNKNOWN_PARAM_OFFSET = None
