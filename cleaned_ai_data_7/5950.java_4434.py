class ReferenceEndpoint:
    def __init__(self, reference: 'Reference', address: int, ref_type: str, is_offcut: bool, source: str):
        self.reference = reference
        self.address = address
        self.ref_type = ref_type
        self.is_offcut = is_offcut
        self.source = source

    @property
    def address(self) -> int:
        return self._address

    @property
    def reference(self) -> 'Reference':
        return self._reference

    @property
    def is_offcut(self) -> bool:
        return self._is_offcut

    @property
    def ref_type(self) -> str:
        return self._ref_type

    @property
    def source(self) -> str:
        return self._source


class Reference:
    pass  # Not implemented in this translation, as it's not provided in the original code


class RefType:
    pass  # Not implemented in this translation, as it's not provided in the original code


class SourceType:
    pass  # Not implemented in this translation, as it's not provided in the original code
