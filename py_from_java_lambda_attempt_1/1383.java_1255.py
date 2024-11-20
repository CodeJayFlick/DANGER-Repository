Here is the translation of the given Java code into equivalent Python:

```Python
import re
from typing import List

class GdbThreadInfo:
    TARGET_ID_LINE_PATTERN0 = re.compile(r"Thread 0x(?P<addr>[0-9A-Fa-f]+)\s+\(LWP (?P(tid)[0-9]+)\)")
    TARGET_ID_LINE_PATTERN1 = re.compile(r"\s+process (?P[tid][0-9]+)\s*")

    def __init__(self, id: str, target_id: str, name: str, state: str, core: str, frames: List):
        self.id = id
        self.target_id = target_id
        self.name = name
        self.state = state
        self.core = core
        self.frames = frames

    @staticmethod
    def parse_info(info) -> 'GdbThreadInfo':
        id = info.get("id")
        target_id = info.get("target-id")
        name = info.get("name")
        state = info.get("state")
        core = info.get("core")
        finfo = info.get("frame")
        frames = []
        for obj in finfo:
            if isinstance(obj, dict):
                frames.append(GdbFrameInfo.parse_info(obj))
        return GdbThreadInfo(id, target_id, name, state, core, frames)

    def __str__(self) -> str:
        return f"<GdbThreadInfo id={self.id},target-id={self.target_id}>"

    def __eq__(self, other):
        if not isinstance(other, GdbThreadInfo):
            return False
        if self.id != other.id or self.target_id != other.target_id:
            return False
        return True

    def get_id(self) -> str:
        return self.id

    def get_target_id(self) -> str:
        return self.target_id

    def get_inferior_name(self) -> str:
        return self.name

    def get_state(self) -> str:
        return self.state

    def get_core(self) -> str:
        return self.core

    def get_frames(self) -> List:
        return self.frames
```

Please note that Python does not have direct equivalent of Java's `BigInteger` and `Integer`. In this translation, I used built-in integer type for simplicity. If you need exact equivalent of these classes in Python, consider using libraries like `gmpy2` or `sympy` which provide similar functionality to Java's `BigInteger`.