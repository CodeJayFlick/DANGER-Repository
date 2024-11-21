class DBTraceParameterSymbolView:
    def __init__(self, manager):
        super().__init__(manager, "PARAMETER", manager.parameter_store)

import abc
from ghidra_program_model_symbol import SymbolType
from ghidra_trace_model_symbol import TraceParameterSymbolView

class AbstractDBTraceSymbolSingleTypeWithAddressView(metaclass=abc.ABCMeta):
    @abstractmethod
    def __init__(self, manager, symbol_type_id, store):
        pass

class DBTraceParameterSymbol:
    pass
