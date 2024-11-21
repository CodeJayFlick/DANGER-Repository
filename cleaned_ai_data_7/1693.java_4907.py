from abc import ABC, abstractmethod
import concurrent.futures as futures

class LldbModelTargetThread(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def get_thread(self) -> 'SBThread':
        raise NotImplementedError("Method not implemented")

    @abstractmethod
    def thread_state_changed_specific(self, state: str, reason: str) -> None:
        raise NotImplementedError("Method not implemented")

    async def set_active(self) -> futures.Future[None]:
        # This is equivalent to the Java code that calls LldbManagerImpl and execute a command.
        pass

    @abstractmethod
    def get_stack(self) -> 'LldbModelTargetStack':
        raise NotImplementedError("Method not implemented")

    @abstractmethod
    def get_executing_processor_type(self) -> str:
        raise NotImplementedError("Method not implemented")
