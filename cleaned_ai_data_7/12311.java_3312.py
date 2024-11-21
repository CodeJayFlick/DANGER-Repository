class Float2DataType:
    dataType = None

    def __init__(self):
        self.__init__(None)

    def __init__(self, dtm=None):
        super().__init__("float2", dtm)
        if not hasattr(self, "dataType"):
            self.dataType = self

    def clone(self, dtm):
        if dtm == self.get_data_type_manager():
            return self
        return Float2DataType(dtm)

    @property
    def length(self):
        return 2

# Create an instance of the class
Float2DataType.dataType = Float2DataType()
