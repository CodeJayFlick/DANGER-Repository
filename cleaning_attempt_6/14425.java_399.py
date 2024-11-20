from typing import Optional

class CakeToppingInfo:
    def __init__(self, id: Optional[int] = None, name: str = "", calories: int = 0):
        self.id = id
        self.name = name
        self.calories = calories

    @property
    def id(self) -> Optional[int]:
        return self._id

    @id.setter
    def id(self, value: Optional[int]):
        if isinstance(value, int):
            self._id = value
        else:
            self._id = None

    def __str__(self) -> str:
        return f"CakeToppingInfo(id={self.id}, name='{self.name}', calories={self.calories})"
