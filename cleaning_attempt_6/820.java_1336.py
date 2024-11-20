class RegisterDescriptor:
    def __init__(self):
        self.containers = []
        self.attributes = [
            {"name": "CONTAINER_ATTRIBUTE_NAME", "type": DbgModelTargetRegisterContainerImpl},
            {"name": None, "type": Void}
        ]

class DbgModelTargetRegisterImpl:
    def __init__(self, registers: 'DbgModelTargetRegisterContainerAndBank', register: 'DbgRegister'):
        self.registers = registers
        self.register = register

        bit_length = register.size() * 8

        super().__init__(registers.model(), key_register(register), "Register")
        self.model().add_model_object(register, self)

    @staticmethod
    def index_register(register: 'DbgRegister'):
        name = register.name()
        if not name:
            return f"UNNAMED,{register.number}"
        return name

    @staticmethod
    def key_register(register: 'DbgRegister'):
        return PathUtils.make_key(index_register(register))

    def change_attributes(self, *args):
        pass  # This method is not implemented in the given Java code.

    def get_bit_length(self) -> int:
        return self.bit_length

    def get_register(self) -> 'DbgRegister':
        return self.register
