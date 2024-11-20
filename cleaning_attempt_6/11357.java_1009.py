from typing import Set, List

class RegisterState:
    def get_keys(self) -> Set[str]:
        pass  # implement this method in your subclass

    def get_vals(self, key: str) -> List[bytes]:
        pass  # implement this method in your subclass

    def is_initialized(self, key: str) -> List[bool]:
        pass  # implement this method in your subclass

    def set_vals(self, key: str, vals: bytes | int, size: int = None, set_initialised: bool = False):
        pass  # implement this method in your subclass

    def dispose(self):
        pass  # implement this method in your subclass
