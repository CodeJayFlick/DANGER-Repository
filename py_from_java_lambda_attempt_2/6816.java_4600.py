Here is the translation of the Java code to Python:
```
class ClangVariableDecl:
    def __init__(self):
        self.datatype = None
        self.typevar = None

    @property
    def datatype(self):
        return self._datatype

    @datatype.setter
    def datatype(self, value):
        self._datatype = value

    @property
    def typevar(self):
        return self._typevar

    @typevar.setter
    def typevar(self, value):
        self._typevar = value

    def restore_from_xml(self, parser, pfactory):
        node = parser.peek()
        super().restore_from_xml(parser, pfactory)
        symref = SpecXmlUtils.decode_long(node.get_attribute("SYMREF"))
        if not isinstance(symref, int) or symref < 0:
            Msg.error(self, f"Invalid symbol reference: {symref} in {self.Parent}")
            return
        sym = pfactory.get_symbol(symref)
        if sym is None:
            Msg.error(self, "Invalid symbol reference")
            return
        self.typevar = sym.high_variable()
        self.datatype = sym.data_type()

class ClangTokenGroup:
    def __init__(self):
        pass

    @abstractmethod
    def restore_from_xml(self, parser, pfactory):
        raise NotImplementedError("Must be implemented by subclass")

class HighVariable:
    def high_variable(self):
        return None  # Not sure what this should do in Python...

class DataType:
    def data_type(self):
        return None  # Not sure what this should do in Python...
```
Note that I had to make some assumptions about the `HighVariable` and `DataType` classes, as they were not defined in the original Java code. In particular, I assumed that these classes would have methods `high_variable()` and `data_type()`, respectively, which return a value of type `HighVariable` or `DataType`. If this is incorrect, please let me know!