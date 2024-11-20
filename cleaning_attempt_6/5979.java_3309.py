class ReferenceEndpointToAddressTableRowMapper:
    def map(self, row_object: 'ReferenceEndpoint', data: 'Program') -> 'int':
        return row_object.get_address()
