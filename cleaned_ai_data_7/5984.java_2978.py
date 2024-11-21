class SymbolToAddressTableRowMapper:
    def map(self, symbol: 'Symbol', program: 'Program') -> 'Address':
        return symbol.get_address()
