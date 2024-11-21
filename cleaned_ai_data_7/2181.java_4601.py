from abc import ABC, abstractmethod
import typing as t

class TargetBreakpointKind(ABC):
    @abstractmethod
    def __str__(self) -> str:
        pass


class Read(TargetBreakpointKind):
    def __str__(self) -> str:
        return "READ"


class Write(TargetBreakpointKind):
    def __str__(self) -> str:
        return "WRITE"


class Hw_Execute(TargetBreakpointKind):
    def __str__(self) -> str:
        return "HW_EXECUTE"


class Sw_Execute(TargetBreakpointKind):
    def __str__(self) -> str:
        return "SW_EXECUTE"


class TargetBreakpointSpec(ABC):
    CONTAINER_ATTRIBUTE_NAME = "container"
    EXPRESSION_ATTRIBUTE_NAME = "expression"
    KINDS_ATTRIBUTE_NAME = "kinds"

    @abstractmethod
    def get_container(self) -> t.Any:
        pass

    @abstractmethod
    def get_expression(self) -> str:
        pass

    @abstractmethod
    def get_kinds(self) -> TargetBreakpointKindSet:
        pass


class TargetBreakpointAction(ABC):
    @abstractmethod
    def breakpoint_hit(
            self, spec: "TargetBreakpointSpec", trapped: t.Any, frame: t.Any, breakpoint: t.Any
    ):
        pass


class TargetBreakpointLocation(t.Generic[t.T]):
    @abstractmethod
    def __init__(self) -> None:
        pass

    @abstractmethod
    def get_locations(self) -> t.List["TargetBreakpointLocation"]:
        pass


class CompletableFuture(ABC):
    @abstractmethod
    def completed_future(self, value: t.Any) -> "CompletableFuture":
        pass

    @abstractmethod
    def collect_successors(
            self, obj: t.Any, target_type: type[t.T]
    ) -> "t.List[TargetBreakpointLocation]":
        pass


class TargetBreakpointKindSet(t.Generic[t.T]):
    EMPTY = None  # TODO: Make hit count part of the common interface?

    @abstractmethod
    def __init__(self) -> None:
        pass

    @abstractmethod
    def get_locations(self) -> t.List["TargetBreakpointLocation"]:
        pass


class TargetTogglable(ABC):
    @abstractmethod
    def toggle(self) -> None:
        pass


# Note: The above Python code is a direct translation of the given Java code. However, it does not include all the necessary imports and may require additional modifications to work correctly.
