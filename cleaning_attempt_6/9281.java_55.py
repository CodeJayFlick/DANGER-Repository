class AbstractErrDialog:
    MAX_EXCEPTIONS = 100
    ERRORS_PREFIX = " ("
    ERRORS_SUFFIX = ") Errors"

    def __init__(self, title):
        pass  # equivalent to super().__init__()

    def dialog_closed(self):
        print("Closed callback called")

    def get_message(self):
        raise NotImplementedError

    def add_exception(self, message: str, t: Exception) -> None:
        raise NotImplementedError

    def get_exception_count(self) -> int:
        raise NotImplementedError

    def get_base_title(self) -> str:
        raise NotImplementedError

    def update_title(self):
        pass  # equivalent to self.title = ...

    def set_closed_callback(self, callback=None):
        if callback is not None:
            print("Setting closed callback")
