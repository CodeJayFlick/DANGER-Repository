class GdbInfoOsCommand:
    def __init__(self, manager: 'GdbManagerImpl', type: str):
        self.manager = manager
        self.type = type

    def encode(self) -> str:
        return f"-info-os {self.type}"

    def complete(self, pending: 'GdbPendingCommand') -> 'GdbTable':
        done_event = pending.check_completion(GdbCommandDoneEvent)
        return GdbTable(done_event.assume_os_data_table(), "item")
