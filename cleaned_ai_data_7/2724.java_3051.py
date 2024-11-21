import typing as t

class HelpInfo(t.Protocol):
    def __call__(self) -> t.Tuple[str]:
        ...

HelpInfo.__annotations__ = {
    "__init_subclass__": lambda cls: setattr(cls, "topic", property(lambda self: [""], setter=lambda s, v: None)),
}

def help_info(topic: str = "", anchor: str = ""):
    return {"topic": topic, "anchor": anchor}
