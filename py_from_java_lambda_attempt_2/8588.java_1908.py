Here's a translation of your Java code into equivalent Python:

```Python
class WithSymbolApplier:
    def __init__(self, applicator, iter):
        self.applicator = applicator
        self.iter = iter
        if not isinstance(iter.next(), AbstractWithMsSymbol):
            raise AssertionError(f"Invalid symbol type: {iter.next().__class__.__name__}")
        self.symbol = AbstractWithMsSymbol(iter.next())

    def apply(self) -> None:
        print("Cannot apply {} directly to program".format(type(self).__name__))
        # TODO: We do not know if this can be applied to a program or not.  We have no examples.

    def apply_to(self, applier_param):
        pass

    def manage_block_nesting(self, applier_param) -> None:
        if isinstance(applier_param, FunctionSymbolApplier):
            function_symbol_applier = FunctionSymbolApplier
            address = self.applicator.get_address(self.symbol)
            # TODO: not sure if get_expression() is correct, but there is no "name."
            function_symbol_applier.begin_block(address, self.symbol.get_expression(), self.symbol.get_length())
```

Please note that Python does not have direct equivalent of Java's package and import statements. Also, Python doesn't support checked exceptions like Java does with `throws PdbException, CancelledException`.