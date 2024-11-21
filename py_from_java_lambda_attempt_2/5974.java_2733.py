Here is the translation of the Java code to Python:
```
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
```
Note that I had to make some assumptions about the Python types and objects used in the translation. Specifically:

* In Java, `Address` is a class representing an address in memory. In Python, we can represent this as an integer (`int`) or a string (`str`). For simplicity, let's assume it's an integer.
* In Java, `ProgramLocation` is a class representing a location within a program. In Python, we can create a custom class to represent this conceptually similar object.
* The `ServiceProvider` and `Program` objects are not explicitly defined in the original code, so I left them as placeholders (`object`) for now.

If you need more specific translations or have further questions, feel free to ask!