class UnknownStatePcodeExecutionException(Exception):
    def __init__(self, language, address, size):
        message = self.get_message(language, address, size)
        super().__init__(message)

    @classmethod
    def get_message(cls, language, address, size):
        if address.address_space.is_register_space:
            reg = language.get_register(address, size)
            if reg is not None:
                return f"No recorded value for register {reg}"
            else:
                registers = [str(r) for r in language.get_registers(address)]
                return f"No recorded value for register(s) {', '.join(registers)}"
        try:
            return f"No recorded value for memory at {address} ({size})"
        except Exception as e:
            raise AssertionError(e)
