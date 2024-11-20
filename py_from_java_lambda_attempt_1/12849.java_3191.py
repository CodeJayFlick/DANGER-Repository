Here is the translation of the Java code to Python:
```
import collections
from typing import Set, List

class LexerMultiplexer:
    def __init__(self, *modes):
        self.modes = modes
        self.stack: List[int] = [0]
        self.channels: Set[int] = {Token.DEFAULT_CHANNEL}

    def get_source_name(self) -> str:
        sb = StringBuilder()
        sb.append("Mux[")
        for i in range(len(modes)):
            if i != 0:
                sb.append(",")
            sb.append(str(i))
            sb.append(":")
            sb.append(modes[i].get_source_name())
        sb.append("]")
        return sb.toString()

    def next_token(self) -> Token:
        mode = self.stack[0]
        src = modes[mode]
        t: Token
        while True:
            t = src.next_token()
            if channels.contains(t.channel):
                break
        return t

    def pop_mode(self) -> int:
        return self.stack.pop()

    def push_mode(self, mode: int) -> None:
        self.stack.append(mode)

    def set_mode(self, mode: int) -> None:
        self.pop_mode()
        self.push_mode(mode)

    def channel_on(self, channel: int) -> None:
        self.channels.add(channel)

    def channel_off(self, channel: int) -> None:
        self.channels.remove(channel)
```
Note that I used the `collections` module for the `Deque` and `Set`, and the `typing` module to specify the types of variables.