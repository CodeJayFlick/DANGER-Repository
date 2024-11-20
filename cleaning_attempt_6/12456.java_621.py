class InjectPayload:
    CALLFIXUP_TYPE = 1
    CALLOTHERFIXUP_TYPE = 2
    CALLMECHANISM_TYPE = 3
    EXECUTABLEPCODE_TYPE = 4

    class InjectParameter:
        def __init__(self, name: str, size: int):
            self.name = name
            self.index = 0
            self.size = size

        @property
        def name(self) -> str:
            return self.name

        @property
        def index(self) -> int:
            return self.index

        @property
        def size(self) -> int:
            return self.size

        def set_index(self, i: int):
            self.index = i

        def __eq__(self, other):
            if not isinstance(other, InjectParameter):
                return False
            if self.index != other.index or self.size != other.size:
                return False
            if self.name != other.name:
                return False
            return True

        def __hash__(self) -> int:
            hash = 0
            for char in self.name:
                hash += ord(char)
            hash *= 79
            hash += self.index
            hash *= 79
            hash += self.size
            return hash


    def __init__(self):
        pass

    @property
    def name(self) -> str:
        raise NotImplementedError("Subclass must implement this method")

    @property
    def type(self) -> int:
        raise NotImplementedError("Subclass must implement this method")

    @property
    def source(self) -> str:
        raise NotImplementedError("Subclass must implement this method")

    @property
    def param_shift(self) -> int:
        raise NotImplementedError("Subclass must implement this method")

    def get_input(self) -> list[InjectParameter]:
        raise NotImplementedError("Subclass must implement this method")

    def get_output(self) -> list[InjectParameter]:
        raise NotImplementedError("Subclass must implement this method")

    @property
    def is_error_placeholder(self) -> bool:
        return False

    def inject(self, context: dict, emit: callable):
        raise NotImplementedError("Subclass must implement this method")

    def get_pcode(self, program: object, con: dict) -> list[object]:
        raise NotImplementedError("Subclass must implement this method")

    @property
    def is_fall_thru(self) -> bool:
        return False

    @property
    def is INCIDENTAL_COPY(self) -> bool:
        return False

    def save_xml(self, buffer: str):
        pass

    def restore_xml(self, parser: object, language: object):
        raise NotImplementedError("Subclass must implement this method")
