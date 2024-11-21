class Attribute:
    def __init__(self, name: str, owning_set):
        self_owning_set = owning_set
        self.attribute_name = name
        self.modification_number = 0
        self.backing_set_modification_number = owning_set.get_modification_number()

    def update(self):
        self.modification_number += 1

    @property
    def owning_set_is_unmodified(self):
        if self.backing_set_modification_number == self_owning_set.get_modification_number():
            return True
        else:
            return False

    @property
    def modification_number(self):
        return self.modification_number

    @property
    def name(self):
        return self.attribute_name

    @property
    def owning_set(self):
        return self_owning_set


class KeyIndexableSet:
    def __init__(self, *args):
        pass  # Implement this class as needed in your Python code.

    def get_modification_number(self) -> int:
        pass  # Implement this method as needed in your Python code.


from abc import ABC, abstractmethod

class AbstractAttribute(ABC):
    @abstractmethod
    def attribute_type(self) -> str:
        pass

    @abstractmethod
    def value_as_string(self, keyed_object: 'KeyedObject') -> str:
        pass

    @abstractmethod
    def clear(self):
        pass


from abc import ABC, abstractmethod

class KeyedObject(ABC):
    @abstractmethod
    def get_key(self) -> object:
        pass
