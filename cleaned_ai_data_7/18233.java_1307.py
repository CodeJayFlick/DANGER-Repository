from enum import Enum

class ExpressionType(Enum):
    AND = "AND"
    OR = "OR"
    SERIES = "SERIES"
    GLOBAL_TIME = "GLOBAL_TIME"
    TRUE = "TRUE"
