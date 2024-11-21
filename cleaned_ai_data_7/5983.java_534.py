class ReferenceToReferenceAddressPairTableRowMapper:
    def map(self, row_object: 'ghidra.program.model.symbol.Reference', program: 'ghidra.program.model.listing.Program') -> tuple:
        return (row_object.get_from_address(), row_object.get_to_address())

# Note that the type hints are not actual Python types, but rather a way to indicate what types of objects should be passed in.
