class FunctionStartParametersFieldLocation:
    def __init__(self, program: 'Program', location_addr: int, function_addr: int, char_offset: int, signature: str):
        super().__init__(program, location_addr, function_addr, char_offset, signature)

    @staticmethod
    def from_xml():
        pass  # Default constructor needed for restoring a program location from XML


class Program:
    pass

class Address:
    pass

# Example usage:

ghidra_program = Program()
location_address = 0x12345678
function_address = 0x87654321
char_offset = 10
signature = "my_function"

field_location = FunctionStartParametersFieldLocation(ghidra_program, location_address, function_address, char_offset, signature)
