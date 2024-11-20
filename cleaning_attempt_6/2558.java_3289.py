class TraceModuleOperations:
    def __init__(self):
        pass

    def get_all_modules(self) -> list:
        """Get all modules"""
        return []

    def get_loaded_modules(self, snap: int) -> list:
        """Get all modules loaded at the given snap"""
        return []

    def get_modules_at(self, snap: int, address: str) -> list:
        """Get modules at the given snap and address"""
        return []

    def get_modules_intersecting(self, lifespan: range, range: tuple) -> list:
        """Get the modules loaded at the given snap intersecting the given address range"""
        return []

    def get_all_sections(self) -> list:
        """Get all sections"""
        return []

    def get_sections_at(self, snap: int, address: str) -> list:
        """Get sections at the given snap and address"""
        return []

    def get_sections_intersecting(self, lifespan: range, range: tuple) -> list:
        """Get the sections loaded at the given snap intersecting the given address range"""
        return []
