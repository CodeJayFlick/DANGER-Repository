Here is the translation of the Java code into Python:

```Python
class VarnodeInfo:
    def __init__(self, program, varnode_type=None):
        self.program = program
        if varnode_type is None:
            self.type = None
            self.address = None
            self.size = None
            self.register = None
        else:
            self.type = varnode_type
            self.address = None
            self.size = None
            self.register = None

    def set_varnode(self, address=None, size=None):
        if address is not None and size is not None:
            self.address = address
            self.size = size
            self.register = get_register(self.program, address, size)
            if address is None:
                return
            if isinstance(address, Register) or self.register is not None:
                self.type = 'Register'
            elif isinstance(address, StackAddress):
                self.type = 'Stack'
            elif isinstance(address, MemoryAddress):
                self.type = 'Memory'
            else:
                raise ValueError("Illegal varnode address type")

    def set_varnode_type(self, varnode_type):
        if varnode_type is not None:
            self.type = varnode_type
            self.address = None

    @property
    def get_register(self):
        return self.register


def get_register(program, address=None, size=None):
    if address is None:
        return None
    if not isinstance(address, Register) and program.get_address_space().has_mapped_registers() is False:
        return None
    if size is None:
        return program.get_register(address)
    register = program.get_register(address, size)
    if register is None:
        register = program.get_register(address)
    return register


class Program:
    def __init__(self):
        pass

    def get_address_space(self):
        # This method should be implemented in the actual class
        raise NotImplementedError("Method not implemented")

    def get_register(self, address=None, size=None):
        # This method should be implemented in the actual class
        raise NotImplementedError("Method not implemented")


class Address:
    def __init__(self):
        pass

    @property
    def is_register_address(self):
        return False


class RegisterAddress(Address):
    def __init__(self):
        super().__init__()

    @property
    def get_address_space(self):
        # This method should be implemented in the actual class
        raise NotImplementedError("Method not implemented")


class StackAddress(Address):
    def __init__(self):
        super().__init__()


class MemoryAddress(Address):
    def __init__(self):
        super().__init__()
```

Please note that this is a direct translation of your Java code into Python. However, the actual implementation may vary depending on how you plan to use these classes in your program.