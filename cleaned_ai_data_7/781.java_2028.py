from abc import ABC, abstractmethod


class DbgModelTargetSession(ABC):
    def get_processes(self) -> 'DbgModelTargetProcessContainer':
        pass  # Implementation missing in original code

    @abstractmethod
    def getSession(self) -> 'DbgSession':
        pass  # Implementation missing in original code

    @abstractmethod
    def console_output(self, output: str, mask: int):
        if not self.is_valid():
            return
        chan = TargetConsole.Channel.STDOUT
        if (mask & DebugOutputFlags.DEBUG_OUTPUT_ERROR) or \
           (mask & DebugOutputFlags.DEBUG_OUTPUT_WARNING):
            chan = TargetConsole.Channel.STDERR
        if output.contains("loaded *kernel* extension dll for usermode"):
            return
        self.fire_console_output(chan, output)

    @abstractmethod
    def prompt_changed(self, prompt: str):
        self.change_attributes([], {"PROMPT_ATTRIBUTE_NAME": prompt}, "Refreshed")

    @abstractmethod
    async def set_active(self) -> 'CompletableFuture[Void]':
        manager = DbgManagerImpl()
        session = self.get_session() or manager.get_event_session()
        return await manager.set_active_session(session)


class CompletableFuture:
    def __init__(self, result):
        self.result = result

    @abstractmethod
    async def then(self, func) -> 'CompletableFuture[Void]':
        pass  # Implementation missing in original code


class DbgSession:
    pass  # Implementation missing in original code


class DbgManagerImpl:
    def get_event_session(self) -> 'DbgSession':
        pass  # Implementation missing in original code

    async def set_active_session(self, session: 'DbgSession') -> 'CompletableFuture[Void]':
        pass  # Implementation missing in original code
