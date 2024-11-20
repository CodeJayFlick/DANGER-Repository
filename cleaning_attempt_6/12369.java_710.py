class Pointer8DataType:
    def __init__(self):
        self.__init__()

    @classmethod
    def put(cls):
        ClassTranslator.put("ghidra.program.model.data.Pointer8", cls.__name__)

    dataType = None

    def __init__(self, dt=None):
        super().__init__()
