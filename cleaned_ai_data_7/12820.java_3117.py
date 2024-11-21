class ThunkedFunctionFieldLocation:
    def __init__(self, program: 'Program', location_addr: int, function_addr: int, thunked_function_addr: int, char_offset: int):
        super().__init__(program=program, location_addr=location_addr, function_addr=function_addr, 0, 0, char_offset)
        self.ref_addr = thunked_function_addr

    def __init__(self):  # Default constructor needed for restoring a program location from XML
        pass


class Program:
    pass


class Address:
    pass
