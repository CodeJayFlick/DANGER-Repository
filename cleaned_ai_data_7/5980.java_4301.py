class ReferenceEndpointToFunctionTableRowMapper:
    def map(self, row_object: 'ReferenceEndpoint', data: 'Program') -> 'Function':
        return next((f for f in data.get_functions() if f.contains(row_object.address)), None)
