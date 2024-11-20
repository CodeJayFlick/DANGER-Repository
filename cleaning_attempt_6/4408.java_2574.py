class SymbolRowObjectToProgramLocationTableRowMapper:
    def map(self, symbol: 'Symbol', program: 'Program') -> 'ProgramLocation':
        return symbol.get_program_location()
