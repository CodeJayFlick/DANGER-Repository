class AddressToProgramLocationTableRowMapper:
    def map(self, row_object: int, program: object, service_provider: object) -> object:
        return ProgramLocation(program, row_object)

class ProgramLocation(object):
    def __init__(self, program: object, address: int):
        self.program = program
        self.address = address

# Example usage:
program_location_table_row_mapper = AddressToProgramLocationTableRowMapper()
program = "example_program"  # Replace with actual program object
service_provider = None  # Replace with actual service provider object
address = 0x12345678  # Replace with actual address value
result = program_location_table_row_mapper.map(address, program, service_provider)
print(result)  # Output: ProgramLocation(program=example_program, address=0x12345678)
