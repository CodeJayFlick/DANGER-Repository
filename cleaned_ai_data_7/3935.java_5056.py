class FunctionRowObjectToFunctionTableRowMapper:
    def map(self, row_object: 'FunctionRowObject', program: 'Program') -> 'Function':
        function = row_object.get_function()
        return function
