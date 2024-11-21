from abc import ABC, abstractmethod


class MemoryRegion(ABC):
    RANGE_ATTRIBUTE_NAME = "range"
    READABLE_ATTRIBUTE_NAME = "readable"
    WRITABLE_ATTRIBUTE_NAME = "writable"
    EXECUTABLE_ATTRIBUTE_NAME = "executable"
    MEMORY_ATTRIBUTE_NAME = "memory"

    def __init__(self):
        pass

    @abstractmethod
    def get_range(self) -> 'AddressRange':
        """Get the address range representing this region"""
        raise NotImplementedError("Method not implemented")

    @abstractmethod
    def is_readable(self) -> bool:
        """Check if this region is readable"""
        raise NotImplementedError("Method not implemented")

    @abstractmethod
    def is_writable(self) -> bool:
        """Check if this region is writable"""
        raise NotImplementedError("Method not implemented")

    @abstractmethod
    def is_executable(self) -> bool:
        """Check if this region is executable"""
        raise NotImplementedError("Method not implemented")

    @abstractmethod
    def get_memory(self) -> 'TargetMemory':
        """Get the memory for this region"""
        raise NotImplementedError("Method not implemented")


class AddressRange(ABC):
    pass


class TargetMemory(ABC):
    pass

