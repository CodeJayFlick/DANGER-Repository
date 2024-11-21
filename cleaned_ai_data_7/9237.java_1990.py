class ObjectStorageAdapterDB:
    def __init__(self):
        self.field_list = []
        self.col = 0
        self.read_only = False

    def construct_from_record(self, rec):
        self.read_only = True
        fields = rec.get_fields()
        for i in range(len(fields)):
            self.field_list.append(fields[i])

    def put_int(self, value):
        if self.read_only:
            raise Exception("Read-only storage adapter")
        self.field_list.append(IntField(value))

    def put_byte(self, value):
        if self.read_only:
            raise Exception("Read-only storage adapter")
        self.field_list.append(ByteField(value))

    def put_short(self, value):
        if self.read_only:
            raise Exception("Read-only storage adapter")
        self.field_list.append(ShortField(value))

    def put_long(self, value):
        if self.read_only:
            raise Exception("Read-only storage adapter")
        self.field_list.append(LongField(value))

    def put_string(self, value):
        if self.read_only:
            raise Exception("Read-only storage adapter")
        self.field_list.append(StringField(value))

    def put_boolean(self, value):
        if self.read_only:
            raise Exception("Read-only storage adapter")
        self.field_list.append(BooleanField(value))

    def get_int(self):
        try:
            return self.field_list[self.col].get_value()
        except IndexError:
            raise IllegalFieldAccessException()

    def get_byte(self):
        try:
            return self.field_list[self.col].get_value()
        except IndexError:
            raise IllegalFieldAccessException()

    def get_short(self):
        try:
            return self.field_list[self.col].get_value()
        except IndexError:
            raise IllegalFieldAccessException()

    def get_long(self):
        try:
            return self.field_list[self.col].get_value()
        except IndexError:
            raise IllegalFieldAccessException()

    def get_boolean(self):
        try:
            return self.field_list[self.col].get_value()
        except IndexError:
            raise IllegalFieldAccessException()

    def get_string(self):
        try:
            return self.field_list[self.col].get_value()
        except IndexError:
            raise IllegalFieldAccessException()

    def put_ints(self, value):
        if self.read_only:
            raise Exception("Read-only storage adapter")
        self.field_list.append(BinaryCodedField(value))

    def get_ints(self):
        try:
            return BinaryCodedField(self.field_list[self.col]).get_value()
        except IndexError:
            raise IllegalFieldAccessException()

    def put_bytes(self, value):
        if self.read_only:
            raise Exception("Read-only storage adapter")
        self.field_list.append(BinaryCodedField(value))

    def get_bytes(self):
        try:
            return BinaryCodedField(self.field_list[self.col]).get_value()
        except IndexError:
            raise IllegalFieldAccessException()

    def put_shorts(self, value):
        if self.read_only:
            raise Exception("Read-only storage adapter")
        self.field_list.append(BinaryCodedField(value))

    def get_shorts(self):
        try:
            return BinaryCodedField(self.field_list[self.col]).get_value()
        except IndexError:
            raise IllegalFieldAccessException()

    def put_longs(self, value):
        if self.read_only:
            raise Exception("Read-only storage adapter")
        self.field_list.append(BinaryCodedField(value))

    def get_longs(self):
        try:
            return BinaryCodedField(self.field_list[self.col]).get_value()
        except IndexError:
            raise IllegalFieldAccessException()

    def put_floats(self, value):
        if self.read_only:
            raise Exception("Read-only storage adapter")
        self.field_list.append(BinaryCodedField(value))

    def get_floats(self):
        try:
            return BinaryCodedField(self.field_list[self.col]).get_value()
        except IndexError:
            raise IllegalFieldAccessException()

    def put_doubles(self, value):
        if self.read_only:
            raise Exception("Read-only storage adapter")
        self.field_list.append(BinaryCodedField(value))

    def get_doubles(self):
        try:
            return BinaryCodedField(self.field_list[self.col]).get_value()
        except IndexError:
            raise IllegalFieldAccessException()

    def put_strings(self, value):
        if self.read_only:
            raise Exception("Read-only storage adapter")
        self.field_list.append(BinaryCodedField(value))

    def get_strings(self):
        try:
            return BinaryCodedField(self.field_list[self.col]).get_value()
        except IndexError:
            raise IllegalFieldAccessException()

    def get_schema(self, version):
        fields = [field.new_field() for field in self.field_list]
        return Schema(version, "key", fields)

    def save(self, rec):
        cnt = len(self.field_list)
        for i in range(cnt):
            rec.set_field(i, self.field_list[i])
