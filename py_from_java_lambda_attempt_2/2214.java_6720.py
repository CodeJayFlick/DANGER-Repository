Here is the translation of the given Java code into equivalent Python:

```Python
from abc import ABC, abstractmethod
import enum
from typing import Set, Mapping, Any

class TargetStepKind(enum.Enum):
    ADVANCE = 1
    FINISH = 2
    INTO = 3
    LINE = 4
    OVER = 5
    OVER_LINE = 6
    SKIP = 7
    RETURN = 8
    UNTIL = 9
    EXTENDED = 10

class TargetSteppable(ABC):
    @abstractmethod
    def get_supported_step_kinds(self) -> Set[TargetStepKind]:
        pass

    @abstractmethod
    async def step(self, kind: TargetStepKind) -> None:
        pass

    def __init__(self):
        self.supported_step_kinds = set()

    def get_supported_step_kinds_name(self) -> str:
        return "supported_step_kinds"

class Steppable(TargetSteppable):
    def __init__(self, supported_step_kinds: Set[TargetStepKind]):
        super().__init__()
        self.supported_step_kinds = supported_step_kinds

    async def step(self, kind: TargetStepKind) -> None:
        if kind not in self.supported_step_kinds:
            raise UnsupportedOperationException("Unsupported Step Kind")
        # implement the actual stepping logic here
        pass

    async def step(self, args: Mapping[str, Any]) -> None:
        await self.step(TargetStepKind.INTO)

    async def step_into(self) -> None:
        await self.step(TargetStepKind.INTO)
```

Note that this is a simplified translation and does not include all the Java code's features. For example, it doesn't handle exceptions or implement actual stepping logic in the `step` method.