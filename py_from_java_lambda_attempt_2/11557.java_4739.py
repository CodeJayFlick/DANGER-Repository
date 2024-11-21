Here is the translation of the Java code into Python:

```Python
class PseudoDisassemblerContext:
    def __init__(self, context):
        self.dis_context = DisassemblerContextImpl(context)

    def get_base_register(self):
        return self.dis_context.get_base_register()

    def set_future_register_value(self, address, value):
        self.dis_context.set_future_register_value(address, value)

    def clear_register(self, register):
        self.dis_context.clear_register(register)

    def get_register(self, name):
        return self.dis_context.get_register(name)

    def get_register_value(self, register):
        return self.dis_context.get_register_value(register)

    def get_registers(self):
        return self.dis_context.get_registers()

    def get_value(self, register, signed=False):
        return self.dis_context.get_value(register, signed)

    def has_value(self, register):
        return self.dis_context.has_value(register)

    def set_register_value(self, value):
        self.dis_context.set_register_value(value)

    def set_value(self, register, value):
        self.dis_context.set_value(register, value)

    def set_value(self, register, addr, value):
        if value is None:
            return
        self.dis_context.set_value(register, addr, value)

    def flow_start(self, address):
        if self.dis_context.is_flow_active():
            self.dis_context.flow_end(self.dis_context.get_address())
        self.dis_context.flow_start(address)

    def get_address(self):
        return self.dis_context.get_address()

    def flow_end(self, address):
        self.dis_context.flow_end(address)

    def flow_to_address(self, target):
        self.dis_context.flow_to_address(target)

    def copy_to_future_flow_state(self, target):
        self.dis_context.copy_to_future_flow_state(target)

    def set_future_register_value(self, from_addr, to_addr, value):
        self.dis_context.set_future_register_value(from_addr, to_addr, value)
```

Note: This translation assumes that the `DisassemblerContextImpl` class is also translated into Python.