from typing import TypeVar, Optional

class Put:
    def __init__(self, key: 'Key', value: object):
        self.key = key
        self.value = value
        self.expected_value: Optional[object] = None

    @property
    def expected_value(self) -> Optional[object]:
        return self.expected_value

    @expected_value.setter
    def expected_value(self, expected_value: object):
        self.expected_value = expected_value

def of(key: 'Key', value: object) -> 'Put':
    return Put(key, value)

def of_with_expected_value(key: 'Key', value: object, expected_value: object) -> 'Put':
    return Put(key, value).expected_value = expected_value
