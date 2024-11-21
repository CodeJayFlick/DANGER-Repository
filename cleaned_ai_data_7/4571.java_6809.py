class AddressableRowObjectToProgramLocationTableRowMapper:
    def map(self, row_object: 'AddressableRowObject', program: 'Program') -> 'ProgramLocation':
        return ProgramLocation(program, row_object.get_address())

# Note: In Python, we don't need a separate class for the mapper,
# as it's not necessary to encapsulate the mapping logic.
