import ctypes

class WrapIDataModelScriptClient:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        super().__init__()
        self.pv_instance = pv_instance

    def report_error(self, err_class: int, hr_fail: int, message: str, line: int, position: int) -> int:
        return ctypes.windll.user32._invokeHR(0x0001, 0, err_class, hr_fail, message.encode(), line, position)

class ByReference(WrapIDataModelScriptClient):
    pass
