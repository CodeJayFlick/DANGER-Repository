class FoundStringToProgramLocationTableRowMapper:
    def map(self, row_object: 'FoundString', data: 'Program', service_provider: object) -> 'ProgramLocation':
        return ProgramLocation(data, row_object.get_address())

# Note: In Python, we don't need an explicit `extends` clause or a constructor.
