class AbstractModelForGdbSteppableTest:
    def get_test(self):
        return self

    def get_expected_steppable_path(self, thread_path: list) -> list:
        return thread_path

    def get_launch_specimen(self) -> str:
        return "PRINT"

    def get_debounce_window_ms(self) -> int:
        return 500
