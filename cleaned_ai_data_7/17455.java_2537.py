import io

class ExternalSortJobPart:
    def __init__(self, type):
        self.type = type

    def execute_for_i_point_reader(self) -> 'IPointReader':
        raise NotImplementedError("Must be implemented by subclass")

    @property
    def type(self):
        return self._type

    class ExternalSortJobPartType(enum.Enum):
        SINGLE_SOURCE = 1
        MULTIPLE_SOURCE = 2
