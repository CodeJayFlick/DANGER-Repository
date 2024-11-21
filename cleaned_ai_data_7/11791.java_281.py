from enum import Enum

class SpaceType(Enum):
    CONSTANT = "IPTR_CONSTANT"  # Special space to represent constants
    PROCESSOR = "IPTR_PROCESSOR"  # Normal spaces modelled by processor
    SPACEBASE = "IPTR_SPACEBASE"  # addresses=offsets off of base register
    INTERNAL = "IPTR_INTERNAL"   # Internally managed temporary space
    FSPEC = "IPTR_FSPEC"         # Special internal
    IOP = "IPTR_IOP"
