class AddressTableToAddressTableRowMapper:
    def map(self, row_object: 'ghidra.AddressTable', program: 'ghidra.Program') -> 'ghidra.Address':
        return row_object.get_top_address()
