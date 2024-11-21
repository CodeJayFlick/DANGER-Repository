import numpy as np

class VelocityExpression:
    def __init__(self):
        pass

    @property
    def velocity(self) -> 'Vector':
        return Vector()

    @velocity.setter
    def velocity(self, value: 'Vector') -> None:
        self.velocity = value


class Vector(np.ndarray):
    def __new__(cls, *args, **kwargs):
        if len(args) == 3 and isinstance(args[0], (int, float)) and isinstance(args[1], (int, float)) and isinstance(args[2], (int, float)):
            return np.array([*args]).reshape(1, -1)
        elif args:
            raise TypeError("Invalid input for Vector")
        else:
            return super().__new__(cls)

    def __array_finalize__(self):
        pass

    @property
    def x(self) -> 'float':
        if self.size == 3:
            return float(self[0, 0])
        elif self.size == 1:
            return float(self)
        else:
            raise TypeError("Invalid Vector size")

    @x.setter
    def x(self, value: 'float') -> None:
        if isinstance(value, (int, float)):
            if self.size == 3:
                self[0, 0] = value
            elif self.size == 1:
                self[:] = [value]
            else:
                raise TypeError("Invalid Vector size")
        else:
            raise TypeError("Value must be a number")

    @property
    def y(self) -> 'float':
        if self.size == 3:
            return float(self[0, 1])
        elif self.size == 1:
            return float(self)
        else:
            raise TypeError("Invalid Vector size")

    @y.setter
    def y(self, value: 'float') -> None:
        if isinstance(value, (int, float)):
            if self.size == 3:
                self[0, 1] = value
            elif self.size == 1:
                self[:] = [value]
            else:
                raise TypeError("Invalid Vector size")
        else:
            raise TypeError("Value must be a number")

    @property
    def z(self) -> 'float':
        if self.size == 3:
            return float(self[0, 2])
        elif self.size == 1:
            return float(self)
        else:
            raise TypeError("Invalid Vector size")

    @z.setter
    def z(self, value: 'float') -> None:
        if isinstance(value, (int, float)):
            if self.size == 3:
                self[0, 2] = value
            elif self.size == 1:
                self[:] = [value]
            else:
                raise TypeError("Invalid Vector size")
        else:
            raise TypeError("Value must be a number")

    def __add__(self, other: 'Vector') -> 'Vector':
        if isinstance(other, Vector):
            return np.array([*map(sum, zip(self, other))]).reshape(1, -1)
        else:
            raise TypeError("Invalid input for addition")
