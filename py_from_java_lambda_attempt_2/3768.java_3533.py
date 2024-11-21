Here is the translation of the Java code to Python:
```
class DataRowObjectToProgramLocationTableRowMapper:
    def map(self, row_object: 'DataRowObject', program: object, service_provider: object) -> object:
        listing = program.get_listing()
        data = listing.get_data_at(row_object.get_address())
        if data is None:
            return None

        return ProgramLocation(program, data.min_address)

class DataRowObject:
    def get_address(self):
        # implement this method
        pass

class ProgramLocation:
    def __init__(self, program: object, address: int):
        self.program = program
        self.address = address

    @property
    def min_address(self) -> int:
        return self.address

class ServiceProvider:
    pass  # not implemented in this example

class Listing:
    def get_listing(self) -> object:
        # implement this method
        pass

    def get_data_at(self, address: int) -> object:
        # implement this method
        pass

# Example usage:
row_object = DataRowObject()
program = Program()  # implement this class
service_provider = ServiceProvider()

location = DataRowObjectToProgramLocationTableRowMapper().map(row_object, program, service_provider)
```
Note that I've used Python's type hinting system to indicate the expected types of variables and method parameters. However, since we're not actually using any specific Java libraries or frameworks in this translation, some classes (like `DataRowObject`, `ProgramLocation`, `ServiceProvider`) are implemented as simple placeholders.

In a real-world scenario, you would need to implement these classes with actual functionality based on the requirements of your project.