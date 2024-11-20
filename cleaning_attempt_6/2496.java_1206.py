from abc import ABC, abstractmethod

class TraceBookmark(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def get_trace(self) -> object:
        """Get the trace associated with this bookmark"""
        raise NotImplementedError("Method not implemented")

    @abstractmethod
    def get_thread(self) -> object:
        """Get the thread containing this bookmark, or None if it's not in a register space"""
        raise NotImplementedError("Method not implemented")

    def set_lifespan(self, lifespan: range):
        """Set the lifespan of this bookmark"""
        pass

    @abstractmethod
    def get_lifespan(self) -> range:
        """Get the lifespan of this bookmark"""
        raise NotImplementedError("Method not implemented")

    @abstractmethod
    def delete(self):
        """Delete this bookmark"""
        raise NotImplementedError("Method not implemented")
