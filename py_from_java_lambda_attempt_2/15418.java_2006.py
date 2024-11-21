Here is the translation of the Java code to Python:

```Python
class Point:
    def __init__(self, x: float, y: float):
        self.x = x
        self.y = y

    @property
    def x(self) -> float:
        return self._x

    @x.setter
    def x(self, value: float):
        self._x = value

    @property
    from typing import Union

    class Point(Union[float, int]):
        def __init__(self, x: Union[float, int], y: Union[float, int]):
            self.x = x
            self.y = y

        @property
        def x(self) -> Union[float, int]:
            return self._x

        @x.setter
        def x(self, value: Union[float, int]):
            self._x = value

        @property
        def y(self) -> Union[float, int]:
            return self._y

        @y.setter
        def y(self, value: Union[float, int]):
            self._y = value