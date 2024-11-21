from enum import Enum

class OpenMode(Enum):
    CREATE = 1
    UPDATE = 2
    READ_ONLY = 3
    UPGRADE = 4
