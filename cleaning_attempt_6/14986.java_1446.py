class AbstractCreature:
    def __init__(self, name: str, size: 'Size', movement: 'Movement', color: 'Color', mass: 'Mass'):
        self.name = name
        self.size = size
        self.movement = movement
        self.color = color
        self.mass = mass

    def __str__(self):
        return f"{self.name} [size={self.size}, movement={self.movement}, color={self.color}, mass={self.mass}]"

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str):
        self._name = value

    @property
    def size(self) -> 'Size':
        return self._size

    @size.setter
    def size(self, value: 'Size'):
        self._size = value

    @property
    def movement(self) -> 'Movement':
        return self._movement

    @movement.setter
    def movement(self, value: 'Movement'):
        self._movement = value

    @property
    def color(self) -> 'Color':
        return self._color

    @color.setter
    def color(self, value: 'Color'):
        self._color = value

    @property
    def mass(self) -> 'Mass':
        return self._mass

    @mass.setter
    def mass(self, value: 'Mass'):
        self._mass = value


class Size:
    pass


class Movement:
    pass


class Color:
    pass


class Mass:
    pass
