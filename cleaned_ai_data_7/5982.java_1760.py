class ReferenceEndpointToReferenceTableRowMapper:
    def map(self, row_object: 'ReferenceEndpoint', data: 'Program') -> 'Reference':
        return row_object.get_reference()
