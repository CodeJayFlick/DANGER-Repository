class WrapIDebugHostTypeSignature:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        super().__init__()

    def get_hash_code(self) -> int:
        # Implement _invokeHR and VTIndices here.
        return 0

    def is_match(self, type: bytes, is_match: bool, wildcard_matches: 'PointerByReference') -> int:
        # Implement _invokeHR and PointerByReference here.
        return 0

    def compare_against(self, type_signature: bytes) -> int:
        # Implement _invokeHR here.
        return 0


class ByReference(WrapIDebugHostTypeSignature):
    pass
