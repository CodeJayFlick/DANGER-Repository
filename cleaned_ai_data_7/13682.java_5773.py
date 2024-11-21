from enum import Enum
from typing import Optional

class Property(Enum):
    MODEL = 'model'

class HasModel:
    def __init__(self) -> None:
        pass

    def get_model(self) -> Optional[str]:
        return next((value for key, value in self.__dict__.items() if str(key).lower().endswith('model')), None)
