class TestLogger:
    def log_state(self, emulator_test_runner):
        pass  # implement this method in your subclass

    def log_state(self, emulator_test_runner: 'EmulatorTestRunner', dump_addr: int, 
                   dump_size: int, element_size: int, element_format: str, comment: str) -> None:
        pass  # implement this method in your subclass

    def log(self, test_group: object, msg: str):
        pass  # implement this method in your subclass

    def log(self, test_group: object, msg: str, t: Exception):
        pass  # implement this method in your subclass
