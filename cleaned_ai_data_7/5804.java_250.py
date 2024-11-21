class ProgramMergeFilter:
    INVALID = -1
    IGNORE = 0
    REPLACE = 1
    MERGE = 2

    PROGRAM_CONTEXT = 0
    BYTES = 1 << PROGRAM_CONTEXT
    INSTRUCTIONS = 1 << (PROGRAM_CONTEXT + 1)
    DATA = 1 << (PROGRAM_CONTEXT + 2)
    REFERENCES = 1 << (PROGRAM_CONTEXT + 3)
    PLATE_COMMENTS = 1 << (PROGRAM_CONTEXT + 4)
    PRE_COMMENTS = 1 << (PROGRAM_CONTEXT + 5)
    EOL_COMMENTS = 1 << (PROGRAM_CONTEXT + 6)
    REPEATABLE_COMMENTS = 1 << (PROGRAM_CONTEXT + 7)
    POST_COMMENTS = 1 << (PROGRAM_CONTEXT + 8)
    SYMBOLS = 1 << (PROGRAM_CONTEXT + 9)
    PRIMARY_SYMBOL = 1 << (PROGRAM_CONTEXT + 10)
    BOOKMARKS = 1 << (PROGRAM_CONTEXT + 11)
    PROPERTIES = 1 << (PROGRAM_CONTEXT + 12)
    FUNCTIONS = 1 << (PROGRAM_CONTEXT + 13)
    EQUATES = 1 << (PROGRAM_CONTEXT + 14)
    PRIMARY_ SYMBOL = 1 << (PROGRAM_CONTEXT + 15)
    FUNCTION_TAGS = 1 << (PROGRAM_CONTEXT + 16)

    NUM_PRIMARY_TYPES = 17
    CODE_UNITS = INSTRUCTIONS | DATA
    COMMENTS = PLATE_COMMENTS | PRE_COMMENTS | EOL_COMMENTS | REPEATABLE_COMMENTS | POST_COMMENTS

    def __init__(self):
        self.filterFlags = [0] * NUM_PRIMARY_TYPES

    @classmethod
    def getPrimaryTypes(cls):
        return [1 << i for i in range(NUM_PRIMARY_TYPES)]

    @staticmethod
    def typeToName(type):
        if type == ProgramMergeFilter.PROGRAM_CONTEXT:
            return "PROGRAM CONTEXT"
        elif type == ProgramMergeFilter.BYTES:
            return "BYTES"
        # ... and so on

    @staticmethod
    def filterToName(filter):
        if filter == ProgramMergeFilter.IGNORE:
            return "IGNORE"
        elif filter == ProgramMergeFilter.REPLACE:
            return "REPLACE"
        elif filter == ProgramMergeFilter.MERGE:
            return "MERGE"

    def __init__(self, type=None, filter=0):
        self.setFilter(type, filter)

    def setFilter(self, type, filter):
        if not isinstance(type, int) or not isinstance(filter, int):
            raise ValueError("Invalid types")
        if not (filter in [ProgramMergeFilter.IGNORE, ProgramMergeFilter.REPLACE, ProgramMergeFilter.MERGE]):
            raise ValueError("Invalid filter")

        for i, pt in enumerate(ProgramMergeFilter.getPrimaryTypes()):
            if type & pt:
                self.filterFlags[i] = min(self.filterFlags[i], filter)

    def getFilter(self, type):
        return self.filterFlags[ProgramMergeFilter.getPrimaryTypes().index(type)]

    def isSet(self):
        for flag in self.filterFlags:
            if flag != ProgramMergeFilter.IGNORE:
                return True
        return False

    def __str__(self):
        buf = ""
        types = ProgramMergeFilter.getPrimaryTypes()
        for type in types:
            filter = self.getFilter(type)
            s = f"  {ProgramMergeFilter.typeToName(type)}={ProgramMergeFilter.filterToName(filter)}\n"
            buf += s
        return buf

    def __eq__(self, other):
        if isinstance(other, ProgramMergeFilter):
            for type in ProgramMergeFilter.getPrimaryTypes():
                if self.filterFlags[types.index(type)] != other.filterFlags[types.index(type)]:
                    return False
            return True
        else:
            return False
