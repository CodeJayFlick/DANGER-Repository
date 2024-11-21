class CakeLayerInfo:
    def __init__(self, id: Optional[int] = None, name: str = "", calories: int = 0):
        self.id = id
        self.name = name
        self.calories = calories

    def __str__(self) -> str:
        return f"CakeLayerInfo(id={self.id}, name='{self.name}', calories={self.calories})"

from typing import Optional

Optional.__init__()
