class GdbConsoleOutputListener:
    def __init__(self):
        pass

    def output(self, channel: str, out: str) -> None:
        """GDB outputted some text"""
