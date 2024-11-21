from abc import ABCMeta, abstractmethod

class GColumnRenderer(metaclass=ABCMeta):
    @abstractmethod
    def get_filter_string(self, t: object, settings) -> str:
        pass

    class ColumnConstraintFilterMode(enum.Enum):
        ALLOW_RENDERER_STRING_FILTER_ONLY = 1
        ALLOW_CONSTRAINTS_FILTER_ONLY = 2
        ALLOW_ALL_FILTERS = 3

    def __init__(self):
        self.column_constraint_filter_mode = GColumnRenderer.ColumnConstraintFilterMode.ALLOW_RENDERER_STRING_FILTER_ONLY

    @property
    def column_constraint_filter_mode(self) -> 'GColumnRenderer.ColumnConstraintFilterMode':
        return self._column_constraint_filter_mode

    @column_constraint_filter_mode.setter
    def column_constraint_filter_mode(self, value: 'GColumnRenderer.ColumnConstraintFilterMode'):
        if not isinstance(value, GColumnRenderer.ColumnConstraintFilterMode):
            raise TypeError("Invalid filter mode")
        self._column_constraint_filter_mode = value

    def create_wrapper_type_exception(self) -> Exception:
        return AssertException("Wrapper column type not expected to be filtered as a String")

class AssertException(Exception):
    pass
