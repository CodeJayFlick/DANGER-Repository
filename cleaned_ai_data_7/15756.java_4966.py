import atexit
from typing import Any

class NativeResource:
    def __init__(self, handle: Any):
        self._handle = [handle]
        self.uid = str(handle)

    @property
    def is_released(self) -> bool:
        return not self._handle[0]

    @property
    def get_handle(self) -> Any:
        if not self.is_released:
            return self._handle[0]
        else:
            raise ValueError("Native resource has been released already.")

    @property
    def uid(self):
        return self.uid

    def close(self):
        pass  # Not implemented


class AutoCloseableResource(NativeResource):
    def __init__(self, handle: Any):
        super().__init__(handle)

    def close(self) -> None:
        raise NotImplementedError("Not implemented.")
