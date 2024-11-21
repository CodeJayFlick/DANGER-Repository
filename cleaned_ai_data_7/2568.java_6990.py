class TraceProgramViewRegisterListing:
    def __init__(self):
        pass

    def get_thread(self) -> 'TraceThread':
        return None  # or any other default value you want to return


from abc import ABC, abstractmethod


class TraceThread(ABC):
    @abstractmethod
    def __str__(self):
        pass
