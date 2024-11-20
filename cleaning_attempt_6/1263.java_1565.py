import socket
from concurrent.futures import Future

class GdbGadpServer:
    def __init__(self):
        self.model = None
        self.server = None

    class GadpSide:
        def __init__(self, model: 'GdbModelImpl', addr: tuple) -> None:
            self.model = model
            self.addr = addr

    def start_gdb(self, gdb_cmd: str, args: list) -> Future[None]:
        return self.model.start_gdb(gdb_cmd, args).then(lambda x: self.server.launch_async_service())

    def get_local_address(self):
        return self.server.get_local_address()

    def console_loop(self):
        self.model.console_loop()

    def terminate(self):
        self.model.terminate()
        self.server.terminate()

    def set_exit_on_closed(self, exit_on_closed: bool):
        self.server.set_exit_on_closed(exit_on_closed)

class GdbModelImpl:
    def __init__(self, pty_factory=None) -> None:
        if pty_factory is not None:
            # TODO: Implement LinuxPtyFactory
            pass

    def start_gdb(self, gdb_cmd: str, args: list):
        return Future()  # Replace with actual implementation

    def console_loop(self):
        raise NotImplementedError("console_loop")

    def terminate(self):
        raise NotImplementedError("terminate")
