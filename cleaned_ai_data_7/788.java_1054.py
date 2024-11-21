class DbgModelTargetSymbolContainer:
    def __init__(self):
        pass

    def get_target_symbol(self, symbol: 'DbgMinimalSymbol') -> 'DbgModelTargetSymbolImpl':
        # This method should be implemented in the subclass.
        raise NotImplementedError("Method not implemented")
