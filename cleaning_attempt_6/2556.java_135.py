from abc import ABC, abstractmethod
import collections

class TraceSection:
    def __init__(self, section_path: str, range):
        self.section_path = section_path
        self.range = range

class AddressRange:
    pass  # No equivalent in Python; you might want to use a tuple or an object with start and end attributes.

class Range:
    pass  # No equivalent in Python; you might want to use a tuple or an object with start and end attributes.

class DuplicateNameException(Exception):
    pass

class AddressOverflowException(Exception):
    pass


class TraceModule(ABC):
    def __init__(self, trace: 'Trace'):
        self.trace = trace
        self.sections = collections.OrderedDict()

    @abstractmethod
    def get_trace(self) -> 'Trace':
        ...

    def add_section(self, section_path: str, range: AddressRange) -> TraceSection:
        if section_path in self.sections:
            raise DuplicateNameException(f"Section {section_path} already exists")
        return TraceSection(section_path, range)

    @property
    def path(self):
        ...  # No equivalent; you might want to use a property with a getter and setter.

    @path.setter
    def set_path(self, value: str):
        ...

    @abstractmethod
    def get_name(self) -> str:
        ...

    @name.setter
    def set_name(self, name: str):
        ...

    @property
    def range(self):
        ...  # No equivalent; you might want to use a property with a getter and setter.

    @range.setter
    def set_range(self, value: AddressRange):
        ...

    @abstractmethod
    def get_base(self) -> 'Address':
        ...

    @base.setter
    def set_base(self, base: 'Address'):
        ...

    @property
    def max_address(self):
        ...  # No equivalent; you might want to use a property with a getter and setter.

    @max_address.setter
    def set_max_address(self, value: 'Address'):
        ...

    @abstractmethod
    def get_length(self) -> int:
        ...

    @length.setter
    def set_length(self, length: int):
        if self.max_address is not None and (self.max_address + 1).value > length:
            raise AddressOverflowException("Length would cause max address to overflow")

    @abstractmethod
    def get_lifespan(self) -> Range:
        ...

    @lifespan.setter
    def set_lifespan(self, lifespan: Range):
        if self.get_name() in [s.section_path for s in self.sections.values()] or any(s.range.overlaps(lifespan) for s in self.sections.values()):
            raise DuplicateNameException("Lifespan would cause name conflicts")

    @abstractmethod
    def get_loaded_snap(self) -> int:
        ...

    @loaded_snap.setter
    def set_loaded_snap(self, loaded_snap: int):
        if any(s.range.overlaps(AddressRange(0, 1)) for s in self.sections.values()):
            raise DuplicateNameException("Loaded snap would cause name conflicts")

    @abstractmethod
    def get_unloaded_snap(self) -> int:
        ...

    @unloaded_snap.setter
    def set_unloaded_snap(self, unloaded_snap: int):
        if any(s.range.overlaps(AddressRange(0, 1)) for s in self.sections.values()):
            raise DuplicateNameException("Unloaded snap would cause name conflicts")

    def get_sections(self) -> collections.OrderedDict:
        return self.sections

    @abstractmethod
    def get_section_by_name(self, section_name: str):
        ...

    @abstractmethod
    def delete(self):
        ...
