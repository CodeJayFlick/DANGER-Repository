Here is the translation of the given Java code into equivalent Python:

```Python
class MDGhidraTestConfiguration:
    def __init__(self, quiet):
        self.mdm = None  # Initialize mdm as None
        super().__init__(quiet)

    @property
    def demangledObject(self):
        return self._demangled_object

    @demangledObject.setter
    def demangledObject(self, value):
        if not isinstance(value, DemangledObject):
            raise TypeError("Demangled object must be of type DemangledObject")
        self._demangled_object = value

    @property
    def demangledGhidraObject(self):
        return self._demangled_ghidra_object

    @demangledGhidraObject.setter
    def demangledGhidraObject(self, value):
        if not isinstance(value, str):
            raise TypeError("Demangled Ghidra object must be a string")
        self._demangled_ghidra_object = value

    @property
    def demangledObjectCheck(self):
        return self._demangled_object_check

    @demangledObjectCheck.setter
    def demangledObjectCheck(self, value):
        if not isinstance(value, DemangledObject):
            raise TypeError("Demangled object check must be of type DemangledObject")
        self._demangled_object_check = value

    def setTruth(self, mdtruth, mstruth, ghtruth, ms2013truth):
        if ghtruth is not None:
            truth = ghtruth
        else:
            truth = mdtruth

    def doDemangleSymbol(self) -> None:
        try:
            demang_item = self.mdm.demangle(mangled, False)
            demangled = str(demang_item)
            self.demangledObject = self.mdm.getObject()
        except MDException as e:
            demang_item = None
            demangled = ""

    def doBasicTestsAndOutput(self) -> None:
        super().doBasicTestsAndOutput()
        if self.demangledObject is not None:
            self.demangledGhidraObject = str(self.demangledObject)
            output_info.append(f"demangl: {self.demangledGhidraObject}\n")
        else:
            self.demangledGhidraObject = ""
            output_info.append("demangled: NO RESULT\n")

    def doExtraProcCheck(self) -> None:
        if (self.demangledObjectCheck is not None and
                self.demangledObject is not None):
            if isinstance(self.demangledObject, type(self.demangledObjectCheck)):
                output_info.append(f"ObjComp: equal NEW: {type(self.demangledObject).__name__}, OLD: {type(self.demangledObjectCheck).__name__}\n")
            else:
                output_info.append(f"ObjComp: notequal NEW: {type(self.demangledObject).__name__}, OLD: {type(self.demangledObjectCheck).__name__}\n")

        elif (self.demangledObject is None and
              self.demangledObjectCheck is not None):
            output_info.append("ObjComp: Not possible -- both null\n")
        else:
            if self.demangledObject is None:
                output_info.append(f"ObjComp: Not possible -- NEW null; OLD: {type(self.demangledObjectCheck).__name__}\n")
            elif self.demangledObjectCheck is None:
                output_info.append(f"ObjComp: Not possible -- OLD null; NEW: {type(self.demangledObject).__name__}\n")

        if ghidra_test_string_compare(output_info, truth_string, self.demangledGhidraObject):
            output_info.append("RESULTS MATCH------******\n")
        else:
            output_info.append("RESULTS MISMATCH------*********************************\n")

    def ghidraTestStringCompare(self, output_info_arg: str, truth_string: str,
                                 ghidra_string: str) -> bool:
        ti = 0
        gi = 0
        pass = True

        while pass:
            if ti < len(truth_string):
                if gi < len(ghidra_string):
                    if truth_string[ti] == ghidra_string[gi]:
                        ti += 1
                        gi += 1
                    elif (truth_string[ti] == ' ') and (ghidra_string[gi] != '_'):
                        ti += 1
                    elif (truth_string[ti] != ' ') and (ghidra_string[gi] == ' '):
                        gi += 1
                    else:
                        pass = False
                        output_info_arg.append(f"truth[{ti}]: {truth_string[ti]} ghidra[{gi}]: {ghidra_string[gi]}\n")
                elif ti < len(truth_string):
                    while ti < len(truth_string) and truth_string[ti] == ' ':
                        ti += 1
                    pass = False
                    output_info_arg.append("early truth termination\n")
                    break
            else if gi < len(ghidra_string):
                while gi < len(ghidra_string) and ghidra_string[gi] == ' ':
                    gi += 1
                pass = False
                output_info_arg.append("early testoutput termination\n")
                break

        return pass


class DemangledObject:
    def __init__(self, value):
        self.value = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        if not isinstance(value, str):
            raise TypeError("Demangled object must be a string")
        self._value = value


class MDMangGhidra:
    pass  # This class is not implemented in the given Java code.
```

Note that I have assumed `MDException` to be an exception type defined elsewhere. Also, some parts of the original Java code were skipped or modified for Python compatibility reasons (e.g., handling exceptions).