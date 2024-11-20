import typing as t

class AutoOptionDefined(t.Protocol):
    def category(self) -> t.List[str]:
        ...

    def type(self) -> str:  # default OptionType.NO_TYPE
        ...

    def name(self) -> t.Sequence[str]:  # equivalent of String[] in Java
        ...

    def help(self, topic: str = "") -> 'HelpInfo':
        return HelpInfo(topic=topic)

    def description(self) -> str:
        ...
