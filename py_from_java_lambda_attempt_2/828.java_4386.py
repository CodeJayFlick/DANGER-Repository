Here is a translation of the Java code into equivalent Python:

```Python
class SymbolContainer:
    def __init__(self):
        self.module = None

    async def request_elements(self, refresh: bool) -> asyncio.Future:
        if not self.module:
            return await asyncio.create_future()

        symbols = []
        with lock(self):  # use a lock to synchronize access
            for symbol in sorted(self.module.list_minimal_symbols().values()):
                target_symbol = self.get_target_symbol(symbol)
                if target_symbol is None:
                    continue

                symbols.append(target_symbol)

        set_elements(symbols, {}, "Refreshed")

    def get_target_symbol(self, symbol: DbgMinimalSymbol) -> DbgModelTargetSymbolImpl | None:
        model_impl = self.module.model
        model_object = model_impl.get_model_object(symbol)
        if model_object is not None:
            return model_object

        return DbgModelTargetSymbolImpl(self, symbol)

class DbgModelTargetModuleImpl:
    def __init__(self):
        pass  # need to implement this class in Python equivalent of Java code

class DbgMinimalSymbol:
    def __init__(self):
        pass  # need to implement this class in Python equivalent of Java code
```

Please note that:

1. This translation is not a direct conversion, but rather an equivalent implementation.
2. The `DbgModelTargetModuleImpl`, and `DbgMinimalSymbol` classes are incomplete implementations as they were missing from the original Java code.
3. In this Python version, I used asyncio for asynchronous operations which might be different than what you would expect in a direct conversion.

The rest of the implementation depends on how these classes (`DbgModelTargetModuleImpl`, `DbgMinimalSymbol`) and other related components are implemented in your specific use case.