class RenameStructureFieldTask:
    def __init__(self, tool, program, panel, token, structure, offset):
        self.structure = structure
        self.offset = offset

    def commit(self):
        # FIXME: How should an existing packed structure be handled? Growing and offset-based placement does not apply
        if not self.structure.isZeroLength():
            len = self.structure.getLength()
            if len < self.offset:
                if not self.structure.getPackingEnabled():
                    print(f"Structure '{self.structure.getName()}' converted to non-packed")
                    self.structure.setPackingEnabled(False)
                self.structure.growStructure(self.offset)

        comp = self.structure.getComponentAt(self.offset)
        if comp.getDataType() == "DEFAULT":  # Is this just a placeholder
            newtype = Undefined1DataType()
            self.structure.replaceAtOffset(self.offset, newtype, 1, None, "Created by retype action")
        else:
            comp.setFieldName(None)

    def getTransactionName(self):
        return "Rename Structure Field"

    def isValid(self, new_name):
        self.new_name = new_name
        comps = self.structure.getDefinedComponents()
        for comp in comps:
            fieldname = comp.getFieldName()
            if fieldname is None:
                continue
            if fieldname == self.new_name:
                return False  # Duplicate Field Name

        return True


class Undefined1DataType:
    pass


# Example usage:

tool = "GHIDRA"
program = "Program"
panel = "DecompilerPanel"
token = "ClangToken"
structure = "Structure"
offset = 0
task = RenameStructureFieldTask(tool, program, panel, token, structure, offset)
