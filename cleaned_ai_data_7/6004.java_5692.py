import typing as t

class TableModelLoader(t.Generic[T]):
    def load(self, accumulator: t.Any, monitor: t.Any) -> None:
        raise NotImplementedError
