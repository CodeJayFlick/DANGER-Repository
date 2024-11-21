class Schema:
    def __init__(self, version: int, key_field: 'Field', key_name: str, fields: list['Field'], field_names: list[str], sparse_columns=None):
        self.version = version
        self.key_type = key_field
        self.key_name = key_name
        self.fields = fields
        self.field_names = field_names
        if len(fields) != len(field_names):
            raise ValueError("fieldNames and fields lengths differ")
        self.is_variable_length = False
        self.fixed_length = 0
        for i, f in enumerate(fields):
            if f.is_variable_length():
                self.is_variable_length = True
            self.fixed_length += f.length()
        try:
            self.initialize_sparse_column_set(sparse_columns)
        except Exception as e:
            raise ValueError(str(e))

    def has_sparse_columns(self) -> bool:
        return self.sparse_column_set is not None

    def is_sparse_column(self, column_index: int) -> bool:
        if self.sparse_column_set is None:
            return False
        return column_index in self.sparse_column_set

    @property
    def use_long_key_nodes(self):
        return not self.force_use_variable_length_key_nodes and isinstance(self.key_type, LongField)

    @property
    def use_variable_key_nodes(self) -> bool:
        return self.force_use_variable_length_key_nodes or self.is_variable_length()

    @property
    def use_fixed_key_nodes(self) -> bool:
        return not (self.use_long_key_nodes or self.use_variable_key_nodes())

    def force_use_of_variable_length_key_nodes(self):
        self.force_use_variable_length_key_nodes = True

    @property
    def encoded_key_field_type(self) -> int:
        return self.key_type.field_type()

    def get_encoded_field_types(self) -> bytes:
        encoded_data_list = []
        for f in self.fields:
            encoded_data_list.append(f.field_type().value)
        if self.sparse_column_set is not None:
            encoded_data_list.append(-1)
            encoded_data_list.extend([b.value for b in self.sparse_column_set])
        return bytes(encoded_data_list)

    def get_version(self) -> int:
        return self.version

    @property
    def is_variable_length_record(self):
        return self.is_variable_length()

    @property
    def fixed_length_record(self) -> int:
        if not self.is_variable_length():
            return self.fixed_length
        else:
            return 0

    def create_record(self, key: 'Field') -> 'DBRecord':
        if self.has_sparse_columns():
            return SparseRecord(self, key)
        else:
            return DBRecord(self, key)

class Field:
    @classmethod
    def get_field(cls, field_class):
        try:
            return cls().new_field()
        except Exception as e:
            raise AssertionError(str(e))

class LongField(Field):
    pass

class ByteField(Field):
    pass

class SparseColumnSet(set[int]):
    pass

class DBRecord:
    pass

class SparseRecord(DBRecord):
    pass
