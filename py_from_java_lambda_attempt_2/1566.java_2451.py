Here is the translation of the given Java code into equivalent Python:

```Python
from typing import Any, TypeVar, List, Set
import asyncio

class LldbPendingCommand:
    def __init__(self, cmd: 'LldbCommand') -> None:
        self.cmd = cmd
        self.evts = set()

    @property
    def command(self) -> 'LldbCommand':
        return self.cmd

    async def finish(self) -> Any:
        try:
            result = await self.cmd.complete()
            self.complete(result)
        except Exception as e:
            self.complete_exceptionally(e)

    async def handle_event(self, evt: 'LldbEvent') -> bool:
        return await self.cmd.handle(evt, self)

    def claim(self, evt: 'LddbEvent') -> None:
        evt.claim(self)
        self.evts.add(evt)

    def steal(self, evt: 'LdbEvent') -> None:
        self.claim(evt)
        evt.steal()

    async def cast_single_event(self, cls: TypeVar('E', bound='LldbEvent')) -> E:
        if len(self.evts) != 1:
            raise ValueError("Command did not claim exactly one event")
        return cls.cast(next(iter(self.evts)))

    async def find_first_of(self, cls: TypeVar('E', bound='LdbEvent')) -> E:
        for evt in self.evts:
            if issubclass(cls, type(evt)):
                return cls.cast(evt)
        raise ValueError("Command did not claim any " + str(cls))

    async def find_all_of(self, cls: TypeVar('E', bound='LldbEvent')) -> List[E]:
        found = []
        for evt in self.evts:
            if issubclass(cls, type(evt)):
                found.append(cls.cast(evt))
        return found

    async def find_single_of(self, cls: TypeVar('E', bound='LdbEvent')) -> E:
        found = await self.find_all_of(cls)
        if len(found) != 1:
            raise ValueError("Command did not claim exactly one " + str(cls))
        return found[0]

    @staticmethod
    def check_completion(completion_event: 'AbstractLldbCompletedCommandEvent', *classes):
        for cls in classes:
            if isinstance(completion_event, cls):
                return completion_event
        if isinstance(completion_event, LldbCommandErrorEvent):
            raise LldbCommandError(completion_event.get_info(), self.cmd)
        else:
            raise ValueError("Command completed with " + str(completion_event) + ", not any of " + str(classes))

    def __str__(self) -> str:
        return f"{super().__str__}({self.cmd})"
```

Please note that Python does not have direct equivalent to Java's `CompletableFuture` and `Future`. The asynchronous programming in this code is achieved using the built-in support for coroutines (async/await syntax).