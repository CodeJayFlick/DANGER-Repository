import typing as t

class Landmark:
    def __init__(self, x: float, y: float, width: float, height: float, points: t.List[t.Tuple[float, float]]):
        self.x = x
        self.y = y
        self.width = width
        self.height = height
        self.points = points

    def get_path(self) -> t.Iterable[t.Tuple[float, float]]:
        return iter(self.points)
