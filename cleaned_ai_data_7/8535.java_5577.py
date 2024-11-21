import logging

class BlockSymbolApplier:
    def __init__(self, applicator: object, iter: object) -> None:
        self.applicator = applicator
        self.iter = iter
        abstract_symbol = next(iter)
        if not isinstance(abstract_symbol, AbstractBlockMsSymbol):
            raise AssertionError(f"Invalid symbol type: {type(abstract_symbol).__name__}")
        self.symbol = abstract_symbol

    def apply(self) -> None:
        logging.info("Cannot apply {} directly to program".format(type(self).__name__))
        return

    def apply_to(self, applier: object) -> None:
        # Do nothing
        pass

    def manage_block_nesting(self, applier: object) -> None:
        address = self.applicator.get_address(self.symbol)
        if isinstance(applier, FunctionSymbolApplier):
            function_symbol_applier = applier
            function_symbol_applier.begin_block(address, self.symbol.name, self.symbol.length)
        elif isinstance(applier, SeparatedCodeSymbolApplier):
            separated_code_symbol_applier = applier
            separated_code_symbol_applier.begin_block(address)
        elif isinstance(applier, ManagedProcedureSymbolApplier):
            managed_procedure_symbol_applier = applier
            managed_procedure_symbol_applyer.begin_block(address, self.symbol.name, self.symbol.length)

class AbstractBlockMsSymbol:
    def __init__(self) -> None:
        pass

    @property
    def name(self) -> str:
        return ""

    @property
    def length(self) -> int:
        return 0

class FunctionSymbolApplier:
    def begin_block(self, address: object, name: str, length: int) -> None:
        # Do nothing
        pass

class SeparatedCodeSymbolApplier:
    def begin_block(self, address: object) -> None:
        # Do nothing
        pass

class ManagedProcedureSymbolApplier:
    def begin_block(self, address: object, name: str, length: int) -> None:
        # Do nothing
        pass
