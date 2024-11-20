class RelocationToAddressTableRowMapper:
    def map(self, relocation: 'Relocation', program: 'Program') -> 'Address':
        return relocation.get_address()
