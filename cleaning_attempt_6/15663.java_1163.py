import random
import math

class HpFloat:
    def __init__(self, name: str, lower: float, upper: float, log: bool):
        self.name = name
        self.log = log
        self.lower = lower
        self.upper = upper

    def random(self) -> float:
        if self.log:
            return math.exp(random.uniform(math.log(lower), math.log(upper)))
        else:
            return random.uniform(lower, upper)

    def __str__(self):
        return f"HPFloat(name='{self.name}', lower={self.lower}, upper={self.upper}, log={self.log})"
