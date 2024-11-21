import typing as t

class AutoServiceProvided(t.Protocol):
    def __call__(self) -> t.Type[t.Any]:
        ...
