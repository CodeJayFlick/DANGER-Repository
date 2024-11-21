class MemSearchResultToFunctionTableRowMapper:
    def map(self, row_object: 'MemSearchResult', program: object) -> 'function':
        function_manager = program.get_function_manager()
        return function_manager.get_function_containing(row_object.address)
