class ReferenceEndpointToProgramLocationTableRowMapper:
    def map(self, row_object: 'ReferenceEndpoint', data: 'Program') -> 'ProgramLocation':
        return ProgramLocation(data, row_object.get_address())

# Note that in Python, we don't need to define classes for every type like Java does.
