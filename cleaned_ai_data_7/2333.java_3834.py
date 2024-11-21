class TraceAddressFactory:
    def __init__(self, language, compiler_spec):
        super().__init__(language, compiler_spec)

    def add_overlay_address_space(self, name: str, preserve_name: bool,
                                    original_space: 'AddressSpace', min_offset: int, max_offset: int) -> 'OverlayAddressSpace':
        return super().add_overlay_address_space(name, preserve_name, original_space, min_offset, max_offset)

    def add_overlay_address_space(self, ov_space: 'OverlayAddressSpace') -> None:
        try:
            super().add_overlay_address_space(ov_space)
        except DuplicateNameException as e:
            raise

    def remove_overlay_space(self, name: str) -> None:
        return super().remove_overlay_space(name)

class AddressSpace:
    pass

class OverlayAddressSpace(AddressSpace):
    pass
