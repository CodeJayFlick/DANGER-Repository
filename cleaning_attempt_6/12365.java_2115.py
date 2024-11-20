class Pointer40DataType:
    def __init__(self):
        self.__init__()

    @classmethod
    def put(cls):
        ClassTranslator.put("ghidra.program.model.data.Pointer40", cls.__name__)

    dataType = None

    def __init__(self, dt=None):
        super().__init__(dt, 5)
