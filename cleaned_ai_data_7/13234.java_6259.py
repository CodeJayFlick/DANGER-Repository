class CodeAttribute:
    def __init__(self):
        self.max_stack = 0
        self.max_locals = 0
        self.code_length = 0
        self.code = bytearray()
        self.exception_table_length = 0
        self.exception_table = []
        self.attributes_count = 0
        self.attributes = []

    def set_max_stack(self, max_stack):
        self.max_stack = max_stack

    def get_max_stack(self):
        return self.max_stack & 0xffff

    def set_max_locals(self, max_locals):
        self.max_locals = max_locals

    def get_max_locals(self):
        return self.max_locals & 0xffff

    def set_code_length(self, code_length):
        self.code_length = code_length

    def get_code_length(self):
        return self.code_length

    def set_code(self, code):
        self.code = bytearray(code)

    def get_code(self):
        return bytes(self.code)

    def set_exception_table_length(self, exception_table_length):
        self.exception_table_length = exception_table_length & 0xffff

    def get_exception_table_length(self):
        return self.exception_table_length

    def set_attributes_count(self, attributes_count):
        self.attributes_count = attributes_count & 0xffff

    def get_attributes_count(self):
        return self.attributes_count

    def set_attributes(self, attributes):
        self.attributes = attributes

    def get_attributes(self):
        return self.attributes
