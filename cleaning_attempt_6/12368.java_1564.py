class Pointer64DataType:
    def __init__(self):
        self.__init__()

    @classmethod
    def put(cls):
        ClassTranslator.put("ghidra.program.model.data.Pointer64", cls.__name__)

    dataType = staticmethod(Pointer64DataType())

    def __init__(self, dt=None):
        super().__init__(dt, 8)
