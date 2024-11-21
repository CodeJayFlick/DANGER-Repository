class ArchiveType:
    BUILTIN = 'BUILTIN'
    FILE = 'FILE'
    PROJECT = 'PROJECT'
    PROGRAM = 'PROGRAM'
    TEST = 'TEST'

    def is_builtin(self):
        return self == ArchiveType.BUILTIN
