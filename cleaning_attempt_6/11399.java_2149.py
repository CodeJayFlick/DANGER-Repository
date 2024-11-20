class AssemblyGrammarException(Exception):
    def __init__(self, msg):
        super().__init__(msg)

    def __init__(self, msg, cause):
        super().__init__(msg)
        self.__cause__ = cause
