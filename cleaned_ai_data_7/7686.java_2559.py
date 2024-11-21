from enum import Enum

class FcgDirection(Enum):
    IN = 1
    IN_AND_OUT = 2
    OUT = 3

    def is_source(self) -> bool:
        return self.value == FcgDirection.IN_AND_OUT.value

    def is_in(self) -> bool:
        return self.value == FcgDirection.IN.value

    def is_out(self) -> bool:
        return self.value == FcgDirection.OUT.value
