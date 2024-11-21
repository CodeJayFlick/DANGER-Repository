class NullTableFilter:
    def accepts_row(self, row_object):
        return True

    def is_sub_filter_of(self, table_filter):
        return False

    def is_empty(self):
        return True

    def __eq__(self, obj):
        if self is obj:
            return True
        elif obj is None:
            return False
        elif type(self) != type(obj):
            return False
        else:
            return True

    def __hash__(self):
        return hash(type(self))
