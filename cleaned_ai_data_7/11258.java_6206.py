import typing as t

class ToolEventName(t.Protocol):
    def __call__(self) -> str: ...

def tool_event_name(value: str) -> ToolEventName:
    return value
