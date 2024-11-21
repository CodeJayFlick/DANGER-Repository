class WrapIDebugDataSpaces2:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        super().__init__()

    def QueryVirtual(self, offset: int, info: dict) -> str:
        return self._invoke_hr('QUERY_VIRTUAL', self.get_pointer(), offset, info)

class ByReference(dict):
    pass
