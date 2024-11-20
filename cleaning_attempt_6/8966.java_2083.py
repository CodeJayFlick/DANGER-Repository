class FunctionRowObjectToFunctionTableRowMapper:
    def map(self, row_object: 'VTFunctionRowObject', program_data: object, service_provider: object) -> 'Function':
        function_manager = program_data.get_function_manager()
        info = row_object.get_info()
        return function_manager.get_function(info.get_function_id())

# Note: In Python, we don't need to define the class as a subclass of ProgramLocationTableRowMapper
# because it's not necessary. We can simply define a regular class with a map method.
