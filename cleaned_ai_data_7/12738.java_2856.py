class AddressFieldLocation:
    def __init__(self, program: 'Program', addr: 'Address', component_path=None,
                 addr_representation: str = None, char_offset=0):
        super().__init__(program, addr, component_path, 0, 0, char_offset)
        self.addr_representation = addr_representation

    @classmethod
    def default(cls, program: 'Program', addr: 'Address'):
        return cls(program, addr)

    def __str__(self) -> str:
        return f"{super().__str__()}, AddressRep={self.addr_representation}"

    def get_address_representation(self) -> str:
        return self.addr_representation

class Program:
    pass
