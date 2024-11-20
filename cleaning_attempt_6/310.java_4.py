import typing as t

class DisassemblyInjectInfo(t.Protocol):
    def lang_ids(self) -> t.List[str]:
        ...

    def priority(self) -> int:
        return 100
