class TypeSpec:
    RAW = type('RAW', (object,), {})

    OBJECT = 'Object'
    BOOLEAN = bool
    BYTE = int
    CHAR = str
    SHORT = int
    INT = int
    LONG = int
    STRING = str
    VOID = None

    BYTE_ARRAY = bytes

    @staticmethod
    def auto():
        return TypeSpec.RAW

    @staticmethod
    def from(future):
        return TypeSpec.auto()

    @classmethod
    def cls(cls, cls_type):
        return TypeSpec.auto()

    @classmethod
    def obj(cls, example):
        return TypeSpec.auto()

    @abstractmethod
    def col(self):
        pass

    @abstractmethod
    def set(self):
        pass

    @abstractmethod
    def list(self):
        pass

    @staticmethod
    def map(key_type, val_type):
        return type('Map', (object,), {})

    @staticmethod
    def pair(l_spec, r_spec):
        return type('Pair', (object,), {})


class FuncArity0:
    @abstractmethod
    def func(self):
        pass


class FuncArity1(FuncArity0):
    @abstractmethod
    def func(self, arg0):
        pass


class FuncArity2(FuncArity1):
    @abstractmethod
    def func(self, arg0, arg1):
        pass


class FuncArity3(FuncArity2):
    @abstractmethod
    def func(self, arg0, arg1, arg2):
        pass


class FuncArity4(FuncArity3):
    @abstractmethod
    def func(self, arg0, arg1, arg2, arg3):
        pass

