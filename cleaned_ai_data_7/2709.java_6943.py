import enum

class DependentService:
    def __init__(self):
        pass

    @property
    def override(self) -> type:
        return Sentinel


@enum.unique
class Sentinel(enum.Enum):
    # None
    pass
