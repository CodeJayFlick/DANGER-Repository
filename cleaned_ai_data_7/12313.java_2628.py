class Float8DataType:
    dataType = None

    def __init__(self):
        self.__init__(None)

    def __init__(self, dtm=None):
        super().__init__("float8", dtm)
        if not hasattr(self, "dataType"):
            self.dataType = type("Float8DataType", (object,), {"__module__": "ghidra.program.model.data"})

    def clone(self, dtm):
        if dtm == self.get_data_type_manager():
            return self
        return Float8DataType(dtm)

    @property
    def length(self):
        return 8

# Initialize the dataType attribute
Float8DataType.dataType = Float8DataType()
