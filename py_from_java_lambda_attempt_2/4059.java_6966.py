Here is the translation of the Java code to Python:
```
import collections
from abc import ABC, abstractmethod

class LocationDescriptor(ABC):
    def __init__(self, program_location: 'ProgramLocation', program: 'Program'):
        self.program_location = program_location
        self.program = program
        self.reference_address_list = []
        self.home_address = None
        self.label = ''
        self.use_dynamic_searching = True

    @abstractmethod
    def get_references(self, accumulator: collections.abc.Accumulator['LocationReference'], monitor):
        pass

    def dispose(self):
        if hasattr(self, 'reference_address_list'):
            self.reference_address_list.clear()
        delattr(self, 'model_freshness_listener')

    def set_model_freshness_listener(self, model_change_listener):
        self.model_freshness_listener = model_change_listener

    @abstractmethod
    def get_highlights(self, text: str, obj, field_factory_class, highlight_color) -> list:
        pass

    def __str__(self):
        return f'{type(self).__name__}: {self.label}'

    def __eq__(self, other):
        if self is other:
            return True
        if not isinstance(other, LocationDescriptor):
            return False
        return (self.program_location == other.program_location and
                self.home_address == other.home_address)

    def get_home_address(self) -> 'Address':
        return self.home_address

    def get_program(self) -> 'Program':
        return self.program

    @abstractmethod
    def doGetReferences(self, accumulator: collections.abc.Accumulator['LocationReference'], monitor):
        pass

    def get_reference_addresses(self, accumulator: collections.abc.Accumulator['LocationReference'], monitor, reload=False):
        if not hasattr(self, 'reference_address_list') or reload:
            self.doGetReferences(accumulator, monitor)
            self.reference_address_list = list(accumulator.get())
            return
        accumulator.extend(list(self.reference_address_list))

    def set_use_dynamic_searching(self, use_dynamic_searching: bool):
        self.use_dynamic_searching = use_dynamic_searching

class ProgramLocation:
    pass  # not implemented in this translation

class Program:
    pass  # not implemented in this translation

class Address:
    pass  # not implemented in this translation
```
Note that I did not implement the `Program`, `Address` and `Reference` classes as they were not provided in the original Java code. You will need to define these classes separately based on your specific requirements.

Also, I used Python's built-in `ABC` class from the `abc` module to create an abstract base class for `LocationDescriptor`. This allows you to use the same syntax and structure as the original Java code while still taking advantage of Python's dynamic typing.