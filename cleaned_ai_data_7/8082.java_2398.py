class AbstractMsSymbol:
    def __init__(self, pdb: 'AbstractPdb', reader):
        if not pdb:
            raise ValueError("pdb cannot be null")
        self.pdb = pdb

    @property
    def pdb(self):
        return self._pdb

    @pdb.setter
    def pdb(self, value):
        self._pdb = value

    def get_pdb_id(self) -> int:
        pass  # abstract method

    def emit(self, builder: 'StringBuilder') -> None:
        builder.append(f"NotImplemented({self.__class__.__name__})")

    @abstractmethod
    def get_symbol_type_name(self) -> str:
        pass


# Note that Python does not have direct equivalent of Java's "abstract" keyword.
# The above class is designed to mimic the abstract class in Java, but it can be instantiated directly.

