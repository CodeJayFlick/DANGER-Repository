import ghidra_framework_plugin as gfp

class ProgramLocationToFunctionContainingTableRowMapper:
    def map(self, row_object: 'ProgramLocation', data: object, service_provider: object) -> object:
        function_manager = data.get_function_manager()
        return function_manager.get_function_containing(row_object.get_address())

# Note: In Python, we don't need to define the class as a subclass of another class
# like we do in Java. Instead, we can simply define it as a regular class.
