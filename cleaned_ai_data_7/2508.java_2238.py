class TraceRegisterContextSpace:
    def __init__(self):
        pass

    def get_address_space(self) -> 'AddressSpace':
        return None  # Replace with actual implementation


from abc import ABC, abstractmethod


class AddressSpace(ABC):
    @abstractmethod
    def __str__(self):
        pass
