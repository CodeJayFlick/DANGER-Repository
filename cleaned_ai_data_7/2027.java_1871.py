from abc import ABC, abstractmethod


class JdiModelTargetExecutionStateful(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def set_execution_state(self, state: str, reason: str) -> None:
        raise NotImplementedError("Method not implemented")
