class IconMaskResourceDataType:
    def __init__(self):
        self.__init__(None, "IconMaskResource", None)

    def __init__(self, path, name, dtm=None):
        super().__init__(path, name, dtm)

    @property
    def description(self):
        return "Icon with Mask stored as a Resource"

    def get_mnemonic(self, settings):
        return "IconMaskRes"

    def clone(self, dtm):
        if dtm == self.get_data_type_manager():
            return self
        return IconMaskResourceDataType(dtm)
