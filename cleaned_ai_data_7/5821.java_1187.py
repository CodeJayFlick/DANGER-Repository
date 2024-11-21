class ExecutionListener:
    def step_completed(self, test_runner):
        pass  # implement this method in your subclass

    def log_write(self, test_runner: 'EmulatorTestRunner', address: int, size: int, values: bytes) -> None:
        pass  # implement this method in your subclass

    def log_read(self, test_runner: 'EmulatorTestRunner', address: int, size: int, values: bytes) -> None:
        pass  # implement this method in your subclass
