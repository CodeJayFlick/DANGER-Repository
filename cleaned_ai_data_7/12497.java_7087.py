class ProcessorContextImpl:
    def __init__(self, language):
        self.language = language
        self.values = {}

    def get_base_context_register(self):
        return self.language.get_context_base_register()

    def get_register(self, name):
        return self.language.get_register(name)

    def get_registers(self):
        return list(self.language.get_registers())

    def get_register_value(self, register):
        if register.base_register not in self.values:
            return None
        bytes = self.values[register.base_register]
        return RegisterValue(register, bytes)

    def get_value(self, register, signed=False):
        if register.base_register not in self.values:
            return None
        value = RegisterValue(register, self.values[register.base_register])
        return value.get_signed_value() if signed else value.get_unsigned_value()

    def has_value(self, register):
        return self.get_value(register) is not None

    def set_value(self, register, value):
        self.set_register_value(RegisterValue(register, value))

    def set_register_value(self, value):
        base_register = value.register.base_register
        if base_register in self.values:
            current_bytes = self.values[base_register]
            combined_value = RegisterValue(base_register, current_bytes).combine_values(value)
            self.values[base_register] = combined_value.to_bytes()
        else:
            self.values[base_register] = value.to_bytes()

    def clear_register(self, register):
        base_register = register.base_register
        if base_register in self.values:
            bytes = self.values.pop(base_register)
            current_value = RegisterValue(base_register, bytes).clear_bit_values(register.base_mask())
            if current_value.has_any_value():
                self.values[base_register] = current_value.to_bytes()

    def clear_all(self):
        self.values.clear()


class RegisterValue:
    def __init__(self, register, value):
        self.register = register
        self.value = value

    @property
    def signed_value(self):
        return self.value

    @property
    def unsigned_value(self):
        return self.value


class Language:
    pass  # This class is not implemented in the given Java code. It's assumed to be a placeholder.
