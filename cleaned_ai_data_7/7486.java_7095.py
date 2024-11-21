class FGVertexType:
    BODY = 'BODY'
    ENTRY = 'ENTRY'
    EXIT = 'EXIT'
    GROUP = 'GROUP'
    SINGLETON = 'SINGLETON'

    def is_entry(self):
        return self == FGVertexType.ENTRY or self == FGVertexType.SINGLETON

    def is_exit(self):
        return self == FGVertexType.EXIT or self == FGVertexType.SINGLETON
