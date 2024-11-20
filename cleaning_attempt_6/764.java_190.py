from concurrent.futures import Future as CompletableFuture
import abc


class DbgModelTargetEventOption(metaclass=abc.ABCMeta):
    @abstractmethod
    def get_option(self) -> int:
        pass

    @abstractmethod
    async def set_option(self, ordinal: int) -> CompletableFuture[None]:
        pass
