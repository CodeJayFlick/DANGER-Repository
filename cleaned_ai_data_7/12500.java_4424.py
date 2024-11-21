class ProgramProcessorContext:
    def __init__(self, context: 'ProgramContext', addr: int):
        self.context = context
        self.addr = addr

    @property
    def base_context_register(self) -> 'Register':
        return self.context.base_context_register

    @property
    def registers(self) -> list['Register']:
        return self.context.registers

    def get_register(self, name: str) -> 'Register':
        return self.context.get_register(name)

    def get_value(self, register: 'Register', signed: bool = False) -> int:
        return self.context.get_value(register, self.addr, signed).intValue()

    @property
    def register_value(self, register: 'Register') -> 'RegisterValue':
        return self.context.register_value(register, self.addr)

    def set_value(self, register: 'Register', value: int) -> None:
        try:
            self.context.set_value(register, self.addr, self.addr, value)
        except Exception as e:
            raise ContextChangeException(str(e))

    @property
    def has_value(self, register: 'Register') -> bool:
        return self.context.get_value(register, self.addr, True) is not None

class RegisterValue:
    pass  # This class does not have a direct equivalent in Python.

# Note that this code assumes the existence of classes ProgramContext,
# Address, BigInteger, and ContextChangeException. These should be defined
# elsewhere in your program.
