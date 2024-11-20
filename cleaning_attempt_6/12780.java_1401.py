class FunctionThunkFieldLocation:
    def __init__(self, program: 'Program', location_addr: int, function_addr: int, char_offset: int, signature: str):
        super().__init__(program, location_addr, function_addr, char_offset, signature)

    def __init__(self):  # Default constructor needed for restoring a program location from XML
        pass

class Program:
    pass

class Address:
    pass

class String:
    pass
