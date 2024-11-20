class MDObjectThrowInfo:
    def __init__(self):
        self.digits = None
        self.data_type = None

    def insert(self, builder):
        super().insert(builder)
        dmang.append_string(builder, "[ThrowInfo," + str(self.digits) + "]{ " + str(self.data_type) + "}")

    def parse_internal(self):
        try:
            # We are assuming that we can have more than one digit.
            # TODO: forward programming to test beyond one digit.
            self.digits = dmang.parse_digits()
            self.data_type = MDDataTypeParser().parse_data_type(dmang, False)
            self.data_type.parse()
        except Exception as e:
            raise MDException(str(e))

class MDMang:
    def parse_digits(self):
        # TODO: implement this method
        pass

    def append_string(self, builder, string):
        # TODO: implement this method
        pass


# Usage example:

dmang = MDMang()
throw_info = MDObjectThrowInfo()

try:
    throw_info.parse_internal()
except Exception as e:
    print(str(e))
