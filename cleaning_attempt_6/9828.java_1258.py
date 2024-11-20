class MultiTextFilterTableFilter:
    def __init__(self, filters: list, transformer, eval_mode):
        self.filters = filters
        self.transformer = transformer
        self.eval_mode = eval_mode

    def is_sub_filter_of(self, table_filter):
        if not isinstance(table_filter, type(self)):
            return False
        
        other = table_filter
        if len(self.filters) != len(other.filters):
            return False
        
        for i in range(len(self.filters)):
            filter1 = self.filters[i]
            filter2 = other.filters[i]
            if not filter1.is_sub_filter_of(filter2):
                return False
        
        clazz = type(self.transformer)
        other_clazz = type(other.transformer)
        return clazz == other_clazz

    def accepts_row(self, row_object):
        if not self.filters:
            return True
        
        column_data = self.transformer(row_object)

        if self.eval_mode == 'AND':
            return all(map(lambda f: self.matches(f, column_data), self.filters))
        
        return any(map(lambda f: self.matches(f, column_data), self.filters))

    def matches(self, filter, column_data):
        return any(map(lambda data: filter.matches(data), column_data))

    def __hash__(self):
        raise NotImplementedError

    def __eq__(self, obj):
        if self is obj:
            return True
        
        if not isinstance(obj, type(self)):
            return False
        
        other = obj
        if self.eval_mode != other.eval_mode:
            return False
        
        if list(self.filters) != list(other.filters):
            return False
        
        if hash(self.transformer) != hash(other.transformer):
            return False
        
        return True

