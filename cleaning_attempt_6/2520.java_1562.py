from typing import TypeVar

class TraceBaseDefinedUnitsView:
    def __init__(self):
        pass

    def clear(self, span: range, address_range: tuple, clear_context: bool = False) -> None:
        raise NotImplementedError("This method is not implemented")

T = TypeVar('T', bound='TraceCodeUnit')

class TraceCodeUnit:
    pass
