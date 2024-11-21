from enum import Enum
from typing import Optional

class Property(Enum):
    TYPE = 'type'

class HasType:
    def __init__(self) -> None:
        pass

    def get_type(self) -> Optional[str]:
        return next((value for key, value in self.__dict__.items() if key == f'{Property.TYPE.value}'), None)
