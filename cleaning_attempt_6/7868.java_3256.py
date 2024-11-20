class MDEncodedNumber:
    def __init__(self):
        self.number = ""
        self.value = None

    def get_value(self):
        return self.value

    def set_value(self, value):
        self.value = value

    def insert(self, builder):
        dmang.insert_spaced_string(builder, str(self.value))

class MDException(Exception):
    pass
