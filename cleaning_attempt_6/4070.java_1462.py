class LocationReferenceToFunctionContainingTableRowMapper:
    def map(self, row_object: 'LocationReference', program: object, service_provider: object) -> object:
        location_of_use = row_object.get_location_of_use()
        function_manager = program.get_function_manager()
        return function_manager.get_function_containing(location_of_use)
