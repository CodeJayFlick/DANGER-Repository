class Float16DataType:
    dataType = None

    def __init__(self):
        self.__init__(None)

    def __init__(self, dtm=None):
        super().__init__("float16", dtm)
        if not hasattr(self, 'dataType'):
            self.dataType = type(self)()

    def clone(self, dtm):
        if dtm == self.get_data_type_manager():
            return self
        return Float16DataType(dtm)

    @property
    def length(self):
        return 16

# Initialize the dataType static variable
Float16DataType.dataType = Float16DataType()
