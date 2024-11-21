from typing import TypeVar, Generic, Callable, Exception

class ExceptionalFunction(Generic[I, R]):
    def __init__(self):
        pass

    @Generic.register
    class _Callable(Callable[[I], R]):
        def apply(self, i: I) -> R:
            raise NotImplementedError("This method must be implemented")

ExceptionalFunction = type('ExceptionalFunction', (ExceptionalFunction,), {'_Callable': _Callable})
