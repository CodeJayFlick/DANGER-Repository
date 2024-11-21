import typing as t

class Predicate(t.Generic[T]):
    def __call__(self, param_t: t.Optional[T]) -> bool:
        ...
