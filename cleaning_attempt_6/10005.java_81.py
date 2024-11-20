import collections

class SpyDropDownWindowVisibilityListener:
    def __init__(self):
        self.events = []

    def window_shown(self, field: 'DropDownTextField') -> None:
        self.events.append(WindowShownInfo(field, True))

    def window_hidden(self, field: 'DropDownTextField') -> None:
        self.events.append(WindowShownInfo(field, False))

    def was_window_shown(self) -> bool:
        if not self.events:
            return False
        info = self.events[-1]
        return info.was_shown

    def was_window_hidden(self) -> bool:
        if not self.events:
            return False
        info = self.events[-1]
        return not info.was_shown

    def reset(self) -> None:
        self.events = []

    def __str__(self) -> str:
        if not self.events:
            return "<no window events>"
        return '\n'.join(str(event) for event in self.events)

class WindowShownInfo:
    def __init__(self, field: 'DropDownTextField', was_shown: bool) -> None:
        self.was_shown = was_shown
        self.source = Exception()
        self.text = field.get_text()

    def __str__(self) -> str:
        return f"{{\nwasShown: {self.was_shown}\ntext: {self.text}\ntrace: {format_exception(self.source)}\n}}"

def format_exception(exception):
    # This is a simplified version of the original Java code
    stack_trace = []
    for frame in exception.__dict__['stack'].frames:
        stack_trace.append(f"{frame.filename}:{frame.lineno}")
    return '\n'.join(stack_trace)
