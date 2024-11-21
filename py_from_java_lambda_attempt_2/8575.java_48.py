Here is the translation of the Java code into Python:

```Python
class PublicSymbolApplier:
    def __init__(self, applicator, iter):
        self.applicator = applicator
        self.iter = iter
        abstract_symbol = next(iter)
        if not isinstance(abstract_symbol, AbstractPublicMsSymbol):
            raise AssertionError(f"Invalid symbol type: {abstract_symbol.__class__.__name__}")
        self.symbol = abstract_symbol

    def apply_to(self, applier):
        # Do nothing.
        pass

    def apply(self):
        try:
            self.symbol_address = self.applicator.get_address(self.symbol)
            name = self.symbol.name
            if self.applicator.is_invalid_address(self.symbol_address, name):
                return
            existing_symbol_address = self.applicator.witness_symbol_name_at_address(name, self.symbol_address)
            if self.symbol_address != existing_symbol_address:
                self.applicator.create_symbol(self.symbol_address, name, True)

                program = self.applicator.get_program()
                if GuidUtil.is_guid_label(program, self.symbol_address, name):
                    try:
                        DataUtilities.create_data(program, self.symbol_address, new(GuidDataType()), -1, False, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA)
                    except CodeUnitInsertionException as e:
                        pass
        except CancelledException as e:
            raise

    @property
    def address(self):
        return self.symbol_address

    @property
    def address_remapped_through_public_symbol(self):
        if not hasattr(self, 'existing_symbol_address') or self.existing_symbol_address is None:
            return self.symbol_address
        else:
            return self.existing_symbol_address

    @property
    def name(self):
        return self.symbol.name


class AbstractPublicMsSymbol:
    pass  # You would need to implement this class in Python, as it's not available by default.


# Usage example:

applicator = Applicator()  # Replace with your actual applicator.
iter = SymbolIterator(applicator)  # Replace with your actual symbol iterator.

applier = PublicSymbolApplier(applicator, iter)
applier.apply()
```

Please note that you would need to implement the `Applicator`, `SymbolIterator` and other classes mentioned in this code.