Here is the equivalent Python code:

```Python
class PinSymbolAction:
    def __init__(self):
        self.description = "Pins the symbol(s) to the address so that it is unaffected by memory block moves or image base changes."
        self.help_location = ("SymbolTablePlugin", "Pinning a Symbol")

    def actionPerformed(self, context):
        program = context.get_program()
        transaction_id = program.start_transaction("Pin Symbol(s)")
        try:
            for symbol in context.get_symbols():
                if isinstance(symbol, (CodeSymbol, FunctionSymbol)) and not symbol.is_external() and not symbol.is_pinned():
                    symbol.set_pinned(True)
        finally:
            program.end_transaction(transaction_id, True)

    def is_enabled_for_context(self, context):
        for symbol in context.get_symbols():
            if isinstance(symbol, (CodeSymbol, FunctionSymbol)) and not symbol.is_external() and not symbol.is_pinned():
                return True
        return False

# Note: Python does not have direct equivalent of Java's package declaration.
```

Note that this code is a translation from the provided Java code to Python. It assumes that there are classes `CodeSymbol`, `FunctionSymbol` and methods like `get_program()`, `start_transaction()`, `end_transaction()` in some context or program class, which you would need to define separately depending on your specific use case.