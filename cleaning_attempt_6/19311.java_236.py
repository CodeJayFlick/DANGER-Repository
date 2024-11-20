import typing as t

class Description(t.Protocol):
    def __call__(self) -> t.List[str]:
        ...
