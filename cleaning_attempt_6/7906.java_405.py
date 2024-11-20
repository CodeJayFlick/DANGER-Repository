class MDObjectUnwindTable:
    def __init__(self, dmang):
        super().__init__(dmang)
        self.object_cpp = None

    def insert(self, builder):
        super().insert(builder)
        if self.object_cpp is not None:
            builder.append("[UnwindTable]{" + str(self.object_cpp) + "}")

    def parse_internal(self):
        try:
            self.object_cpp = MDObjectCPP()
            self.object_cpp.parse()
            # MDMANG SPECIALIZATION USED.
            self.object_cpp = dmang.get_embedded_object(self.object_cpp)
        except Exception as e:
            raise MDException(str(e))

class MDObjectReserved:
    def __init__(self, dmang):
        pass

    def insert(self, builder):
        pass

class MDObjectCPP:
    def parse(self):
        pass
