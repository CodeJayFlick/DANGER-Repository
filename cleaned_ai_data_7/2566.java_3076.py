class TraceProgramViewListing:
    def __init__(self):
        pass

    def get_program(self) -> 'TraceProgramView':
        return None  # Replace with actual implementation


from abc import ABC, abstractmethod


class SnapSpecificTraceView(ABC):
    @abstractmethod
    def __str__(self):
        pass


class TraceProgramView:
    def __init__(self):
        pass

    def __str__(self) -> str:
        return "This is a trace program view"
