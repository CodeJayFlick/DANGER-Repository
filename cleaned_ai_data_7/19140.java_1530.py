from enum import Enum

class WithType:
    def __init__(self, type: 'Enum', value):
        self.type = type
        self.value = value

    @property
    def get_type(self) -> 'Enum':
        return self.type

    @property
    def get_value(self) -> object:
        return self.value

def of(type: Enum, value) -> 'WithType':
    return WithType(type, value)
