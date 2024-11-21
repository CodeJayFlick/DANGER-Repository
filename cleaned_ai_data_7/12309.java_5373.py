class Float10DataType:
    dataType = None

    def __init__(self):
        self.__init__(None)

    def __init__(self, dtm=None):
        super().__init__("float10", dtm)
        if not hasattr(self, 'dataType'):
            self.dataType = type(self)()

    def clone(self, dtm):
        if dtm == self.get_data_type_manager():
            return self
        return Float10DataType(dtm)

    @property
    def length(self):
        return 10

# Initialize the dataType attribute
Float10DataType.dataType = Float10DataType()
