class LldbDebugOutputCallbacks:
    def __init__(self, manager):
        self.manager = manager

    def output(self, mask: int, text: str) -> None:
        self.manager.process_event(LldbConsoleOutputEvent(mask, text))

class LldbConsoleOutputEvent:
    def __init__(self, mask: int, text: str):
        self.mask = mask
        self.text = text
