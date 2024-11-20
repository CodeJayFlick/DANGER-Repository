class IntegerColumnAdapter:
    def get_value_class(self):
        return int

    def get_key_value(self, rec):
        key_field = rec.get_key_field()
        if isinstance(key_field, int):
            return int(key_field)
        else:
            raise ValueError("Expected IntField")

    def get_value(self, rec, col):
        return int(rec.get_int_value(col))
