Here is the translation of the given Java code into Python:

```Python
class RainbowFishV2:
    def __init__(self, name: str, age: int, length_meters: float, weight_tons: float):
        pass  # equivalent to super().__init__()

    @property
    def sleeping(self) -> bool:
        return self._sleeping

    @sleeping.setter
    def sleeping(self, value: bool):
        self._sleeping = value

    @property
    def hungry(self) -> bool:
        return self._hungry

    @hungry.setter
    def hungry(self, value: bool):
        self._hungry = value

    @property
    def angry(self) -> bool:
        return self._angry

    @angry.setter
    def angry(self, value: bool):
        self._angry = value

# equivalent to the constructor with all parameters
def __init__(self, name: str, age: int, length_meters: float, weight_tons: float,
             sleeping: bool, hungry: bool, angry: bool):
    super().__init__()
    self.sleeping = sleeping
    self.hungry = hungry
    self.angry = angry

# equivalent to the constructor without parameters
def __init__(self):
    pass  # nothing else needed here