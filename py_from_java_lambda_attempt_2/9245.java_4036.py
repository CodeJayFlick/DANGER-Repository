Here is the translation of the given Java code into Python:

```Python
class SparseRecord:
    def __init__(self, schema, key):
        super().__init__(schema, key)

    def compute_length(self):
        len = 1  # sparse field count always written as byte after non-sparse fields
        for i in range(len(self.get_fields())):
            f = self.get_fields()[i]
            if self.schema.is_sparse_column(i):
                if not f.isNull():
                    # sparse field if present will be prefixed by a byte indicating the column index
                    len += f.length() + 1
                else:
                    len += f.length()
            else:
                len += f.length()

        return len

    def write(self, buf, offset):
        sparse_field_indexes = []
        for i in range(len(self.get_fields())):
            if self.schema.is_sparse_column(i):
                if not self.get_fields()[i].isNull():
                    sparse_field_indexes.append(i)
            else:
                offset = self.get_fields()[i].write(buf, offset)

        # write sparse field count
        buf.put(offset++, bytes([sparse_field_indexes.__len__()]))
        for i in range(len(sparse_field_indexes)):
            f = self.get_fields()[sparse_field_indexes[i]]
            if not f.isNull():
                # sparse field if present will be prefixed by a byte indicating the column index
                buf.put(offset++, bytes([i]))  # sparse field index
                offset = f.write(buf, offset)  # sparse field data

        self.dirty = False

    def read(self, buf, offset):
        for i in range(len(self.get_fields())):
            if self.schema.is_sparse_column(i):
                self.get_fields()[i].setNull()
            else:
                offset = self.get_fields()[i].read(buf, offset)

        sparse_field_count = int.from_bytes(buf.read(1), 'big')
        for _ in range(sparse_field_count):
            index = buf.read(1)[0]
            offset = self.get_fields()[index].read(buf, offset)  # sparse field data

        self.dirty = False

    def change_in_sparse_storage(self, col_index, new_value):
        if not self.schema.is_sparse_column(col_index):
            return False
        old_sparse = self.get_field(col_index).is_null()
        new_sparse = new_value == 0
        return old_sparse != new_sparse

    def set_field(self, col_index, value):
        if value is None:
            if not self.schema.is_sparse_column(col_index):
                raise ValueError("null value supported for sparse column only")
            value = self.get_field(col_index).new_field()
            value.set_null()

        super().set_field(col_index, value)

    def set_long_value(self, col_index, new_value):
        if self.change_in_sparse_storage(col_index, new_value):
            self.invalidate_length()

        super().set_long_value(col_index, new_value)

    def set_int_value(self, col_index, new_value):
        if self.change_in_sparse_storage(col_index, new_value):
            self.invalidate_length()

        super().set_int_value(col_index, new_value)

    def set_short_value(self, col_index, new_value):
        if self.change_in_sparse_storage(col_index, new_value):
            self.invalidate_length()

        super().set_short_value(col_index, new_value)

    def set_byte_value(self, col_index, new_value):
        if self.change_in_sparse_storage(col_index, new_value):
            self.invalidate_length()

        super().set_byte_value(col_index, new_value)

    def set_boolean_value(self, col_index, new_value):
        if self.change_in_sparse_storage(col_index, 1 if new_value else 0):
            self.invalidate_length()

        super().set_boolean_value(col_index, new_value)
```

Note: This translation assumes that the `DBRecord`, `Field`, and other classes are defined elsewhere in your Python code.