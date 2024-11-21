import typing as t

class CommandEvent:
    def __init__(self, sender: 'CommandSender', command: str, args: t.Optional[t.List[str]] = None):
        self.sender = sender
        self.command = command
        self.args = args if args is not None else []

    @property
    def sender(self) -> 'CommandSender':
        return self._sender

    @property
    def command(self) -> str:
        return self._command

    @property
    def args(self) -> t.Optional[t.List[str]]:
        return self._args


class CommandSender:
    pass  # Replace with actual implementation or leave as abstract class


HandlerList = object()  # Replace with actual implementation or leave as placeholder


def get_handler_list():
    return HandlerList

__all__ = ['CommandEvent', 'CommandSender']
