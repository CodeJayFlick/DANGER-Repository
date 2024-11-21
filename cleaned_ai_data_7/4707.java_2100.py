import io

class NullSectionProvider:
    def __init__(self):
        pass

    def get_section_as_byte_provider(self, section_name: str) -> bytes:
        return b''

    def has_section(self, *section_names: str) -> bool:
        return True

    def close(self):
        pass
