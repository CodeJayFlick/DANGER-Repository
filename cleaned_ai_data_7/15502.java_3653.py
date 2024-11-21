import numpy as np
from typing import List

class ActionSpace(List):
    def __init__(self):
        super().__init__()

    def random_action(self) -> list:
        return [np.random.choice(list(self)) for _ in range(len(self))]
