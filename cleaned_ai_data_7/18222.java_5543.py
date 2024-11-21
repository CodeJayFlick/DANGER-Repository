class Field:
    def __init__(self, data_type):
        self.data_type = data_type
        if data_type == 'DOUBLE':
            self.bool_v = None
            self.int_v = None
            self.long_v = None
            self.float_v = None
            self.double_v = None
            self.binary_v = None
        elif data_type == 'FLOAT':
            self.bool_v = None
            self.int_v = None
            self.long_v = None
            self.float_v = None
            self.double_v = None
            self.binary_v = None
        elif data_type == 'INT64':
            self.bool_v = None
            self.int_v = None
            self.long_v = 0
            self.float_v = None
            self.double_v = None
            self.binary_v = None
        elif data_type == 'INT32':
            self.bool_v = None
            self.int_v = 0
            self.long_v = None
            self.float_v = None
            self.double_v = None
            self.binary_v = None
        elif data_type == 'BOOLEAN':
            self.bool_v = False
            self.int_v = None
            self.long_v = None
            self.float_v = None
            self.double_v = None
            self.binary_v = None
        elif data_type == 'TEXT':
            self.bool_v = None
            self.int_v = None
            self.long_v = None
            self.float_v = None
            self.double_v = None
            self.binary_v = None

    def copy(self, field):
        out = Field(field.data_type)
        if out.data_type:
            if out.data_type == 'DOUBLE':
                out.set_double_v(field.get_double_v())
            elif out.data_type == 'FLOAT':
                out.set_float_v(field.get_float_v())
            elif out.data_type == 'INT64':
                out.set_long_v(field.get_long_v())
            elif out.data_type == 'INT32':
                out.set_int_v(field.get_int_v())
            elif out.data_type == 'BOOLEAN':
                out.set_bool_v(field.get_bool_v())
            elif out.data_type == 'TEXT':
                out.set_binary_v(field.get_binary_v())
        return out

    def get_data_type(self):
        return self.data_type

    def set_double_v(self, double_v):
        if not self.data_type:
            raise NullFieldException
        self.double_v = double_v

    def get_double_v(self):
        if not self.data_type:
            raise NullFieldException
        return self.double_v

    def set_float_v(self, float_v):
        if not self.data_type:
            raise NullFieldException
        self.float_v = float_v

    def get_float_v(self):
        if not self.data_type:
            raise NullFieldException
        return self.float_v

    def set_long_v(self, long_v):
        if not self.data_type:
            raise NullFieldException
        self.long_v = long_v

    def get_long_v(self):
        if not self.data_type:
            raise NullFieldException
        return self.long_v

    def set_int_v(self, int_v):
        if not self.data_type:
            raise NullFieldException
        self.int_v = int_v

    def get_int_v(self):
        if not self.data_type:
            raise NullFieldException
        return self.int_v

    def set_bool_v(self, bool_v):
        if not self.data_type:
            raise NullFieldException
        self.bool_v = bool_v

    def get_bool_v(self):
        if not self.data_type:
            raise NullFieldException
        return self.bool_v

    def set_binary_v(self, binary_v):
        if not self.data_type:
            raise NullFieldException
        self.binary_v = binary_v

    def get_binary_v(self):
        if not self.data_type:
            raise NullFieldException
        return self.binary_v

    def get_string_value(self):
        if not self.data_type:
            return 'null'
        if self.data_type == 'BOOLEAN':
            return str(self.bool_v)
        elif self.data_type in ['INT32', 'INT64']:
            return str(self.int_v) if self.data_type == 'INT32' else str(self.long_v)
        elif self.data_type in ['FLOAT', 'DOUBLE']:
            return str(self.float_v) if self.data_type == 'FLOAT' else str(self.double_v)
        elif self.data_type == 'TEXT':
            return str(self.binary_v)

    def __str__(self):
        return self.get_string_value()

    def get_object_value(self, data_type):
        if not self.data_type:
            return None
        if data_type in ['DOUBLE', 'FLOAT']:
            return self.double_v if data_type == 'DOUBLE' else self.float_v
        elif data_type in ['INT64', 'INT32']:
            return self.long_v if data_type == 'INT64' else self.int_v
        elif data_type == 'BOOLEAN':
            return self.bool_v
        elif data_type == 'TEXT':
            return self.binary_v

    @staticmethod
    def get_field(value, data_type):
        field = Field(data_type)
        if value is None:
            return None
        if data_type in ['INT32', 'INT64']:
            field.set_int_v(int(value))
        elif data_type == 'FLOAT':
            field.set_float_v(float(value))
        elif data_type == 'DOUBLE':
            field.set_double_v(double(value))
        elif data_type == 'BOOLEAN':
            field.set_bool_v(bool(value))
        elif data_type == 'TEXT':
            field.set_binary_v(Binary(value))
        return field
