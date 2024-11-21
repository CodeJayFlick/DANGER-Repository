import asyncio
from typing import List

class ProcMaker:
    def __init__(self, client: object, cmd_line: str):
        self.client = client
        self.cmd_line = cmd_line
        self.control = client.get_control()

    async def start(self) -> None:
        await self.client.set_event_callbacks(
            NoisyDebugEventCallbacksAdapter(DebugStatus.NO_CHANGE)
        )
        await self.client.output_callbacks(
            DebugOutputCallbacks()
        )

        print(f"Starting {self.cmd_line} with client {self.client}")
        self.control.execute(f".create {self.cmd_line}")
        await self.control.wait_for_event()

    async def kill(self) -> None:
        print("Killing", self.cmd_line)
        self.control.execute(".kill")
        await self.control.wait_for_event()
        exit_code = await proc_exit
        assert exit_code is not None

    async def exec_capture(self, command: str) -> List[str]:
        output_capture = []
        try:
            self.control.execute(command)
            for line in iter(lambda: input(), ''):
                if line == '':
                    break
                output_capture.append(line.strip())
        finally:
            pass  # No equivalent to Java's null assignment

    async def close(self) -> None:
        if proc_info.done() and not proc_exit.done():
            await self.kill()

class DebugStatus(int):
    NO_CHANGE = 0
    BREAK = 1


class DebugProcessInfo:
    def __init__(self, *args: object):
        pass  # No equivalent to Java's constructor

    async def get(self) -> None:
        pass  # No equivalent to Java's method


class DebugThreadInfo:
    def __init__(self, *args: object):
        pass  # No equivalent to Java's constructor

    async def get(self) -> None:
        pass  # No equivalent to Java's method


class CompletableFuture:
    def __init__(self, value=None):
        self.value = value
        self.done = False

    @property
    def done(self):
        return self._done

    @done.setter
    def done(self, state: bool):
        self._done = state

    async def complete(self, value) -> None:
        if not self.done:
            self.value = value
            self.done = True


class NoisyDebugEventCallbacksAdapter(DebugClient.EventCallbacks):
    def __init__(self, debug_status: DebugStatus):
        super().__init__()
        self.debug_status = debug_status

    async def create_process(self, process_info) -> None:
        await super().create_process(process_info)
        proc_info.complete(process_info)

    async def create_thread(self, thread_info) -> None:
        await super().create_thread(thread_info)
        thread_info.complete(thread_info)

    async def exit_process(self, exit_code: int) -> None:
        await super().exit_process(exit_code)
        proc_exit.complete(exit_code)


class DebugOutputCallbacks(DebugClient.OutputCallbacks):
    async def output(self, mask: int, text: str) -> None:
        print(text)
