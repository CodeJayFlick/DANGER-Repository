class LocalOptimizedSymbolApplier:
    def __init__(self, applicator, iter):
        self.applicator = applicator
        self.iter = iter
        abstract_symbol = next(iter)
        if not isinstance(abstract_symbol, AbstractLocalSymbolInOptimizedCodeMsSymbol):
            raise AssertionError(f"Invalid symbol type: {type(abstract_symbol).__name__}")
        self.symbol = abstract_symbol

    def apply(self):
        print("Cannot apply this directly to program")

    def apply_to(self, applier):
        if not self.applicator.get_pdb_applicator_options().apply_function_variables():
            return
        if isinstance(applier, FunctionSymbolApplier):
            function_symbol_applier = applier
            do_work(function_symbol_applier)

    def do_work(self, function_symbol_applier):
        # TODO: Not doing anything with the information yet.
        self.symbol.get_local_variable_flags()
        self.symbol.name
        self.symbol.type_record_number

        while iter.has_next() and isinstance(next(iter), AbstractDefinedSingleAddressRangeMsSymbol):
            if self.applicator.check_canceled():
                return
            range_applier = DefinedSingleAddressRangeSymbolApplier(self.applicator, iter)
            range_applier.apply_to(applier=self)

class FunctionSymbolApplier:
    pass

class DefinedSingleAddressRangeSymbolApplier:
    def __init__(self, applicator, iter):
        self.applicator = applicator
        self.iter = iter

    def apply(self):
        # TODO: Not doing anything with the information yet.
        pass

# Usage example:

applicator = PdbApplicator()  # Replace this with your actual applicator class instance
iter = AbstractMsSymbolIterator()
applier = LocalOptimizedSymbolApplier(applicator, iter)
