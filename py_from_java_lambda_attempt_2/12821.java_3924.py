Here is the equivalent Python code:

```Python
class UserDataChangeRecord:
    def __init__(self, property_name: str, old_value=None, new_value=None):
        self.property_name = property_name
        self.old_value = old_value
        self.new_value = new_value

    @property
    def property_name(self) -> str:
        return self._property_name

    @property_name.setter
    def property_name(self, value: str):
        self._property_name = value

    @property
    def old_value(self) -> object:
        return self._old_value

    @old_value.setter
    def old_value(self, value: object):
        self._old_value = value

    @property
    def new_value(self) -> object:
        return self._new_value

    @new_value.setter
    def new_value(self, value: object):
        self._new_value = value


class DomainObjectChangeRecord:
    pass  # This class is not implemented in the original code.