class AddressToFunctionContainingTableRowMapper:
    def map(self, row_object: 'Address', program: object) -> 'Function':
        function_manager = program.get_function_manager()
        return function_manager.get_function_containing(row_object)

if __name__ == '__main__':
    pass
